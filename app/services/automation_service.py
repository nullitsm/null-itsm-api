"""Automation rules service (migration 0014, Phase 4).

A rule is ``trigger -> conditions -> actions`` against a real entity.
Evaluation is explicit: :func:`evaluate_rules` is called with a real
event (trigger + entity type + entity id) — by the API endpoint, and
later by the ticket/SLA routers at integration — and for each enabled
rule matching that trigger it:

1. loads the real entity (org-scoped; a missing or foreign entity
   evaluates nothing),
2. checks every condition against the entity's actual field values,
3. only when ALL conditions match, applies each action through the
   shared :func:`workflow_service.apply_action` executor (the same
   real effects a workflow step performs),
4. writes ONE ``automation_runs`` row recording exactly which actions
   ran and their outcome.

A rule whose conditions do not match runs nothing and records nothing
— there is no ``automation_runs`` row for a non-firing evaluation, and
no action is ever recorded as done when it did not run. A firing rule
whose action fails mid-way records ``partial`` (or ``failed`` when
nothing applied) with the error, so the run history is honest about
what actually happened.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.workflows import (
    ACTION_TYPES,
    AUTOMATION_TRIGGERS,
    CONDITION_FIELDS,
    CONDITION_OPERATORS,
    AutomationRule,
    AutomationRun,
)
from app.services.workflow_service import PRIORITIES, TICKET_STATUSES, apply_action, load_entity

# Conditionable fields and their value domains, per entity type.
FIELD_DOMAINS: dict[str, dict[str, set[str] | None]] = {
    "ticket": {
        "status": TICKET_STATUSES,
        "priority": PRIORITIES,
        "category": None,  # free text
        "assignee_id": None,  # uuid or null
        "sla_breached": None,  # boolean
    },
}


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def validate_conditions(conditions: object, entity_type: str) -> list[dict]:
    """Validate a condition list; returns the normalized list (400 on bad input)."""
    allowed = CONDITION_FIELDS.get(entity_type, set())
    if not isinstance(conditions, list):
        raise _bad("conditions must be a list")
    normalized: list[dict] = []
    for i, raw in enumerate(conditions):
        if not isinstance(raw, dict):
            raise _bad(f"conditions[{i}] must be an object")
        field = raw.get("field")
        operator = raw.get("operator")
        if field not in allowed:
            raise _bad(f"conditions[{i}].field must be one of {sorted(allowed)}")
        if operator not in CONDITION_OPERATORS:
            raise _bad(f"conditions[{i}].operator must be one of {sorted(CONDITION_OPERATORS)}")
        if operator in {"eq", "ne", "in", "not_in"} and "value" not in raw:
            raise _bad(f"conditions[{i}].value is required for operator {operator}")
        if operator in {"in", "not_in"} and not isinstance(raw.get("value"), list):
            raise _bad(f"conditions[{i}].value must be a list for operator {operator}")
        domain = FIELD_DOMAINS.get(entity_type, {}).get(field)
        if domain is not None and operator in {"eq", "ne", "in", "not_in"}:
            values = raw["value"] if isinstance(raw["value"], list) else [raw["value"]]
            bad = [v for v in values if v not in domain]
            if bad:
                raise _bad(f"conditions[{i}].value {bad} is not valid for field {field}")
        normalized.append({"field": field, "operator": operator, "value": raw.get("value")})
    return normalized


def validate_actions(actions: object) -> list[dict]:
    """Validate an action list; returns the normalized list (400 on bad input)."""
    if not isinstance(actions, list):
        raise _bad("actions must be a list")
    if not actions:
        raise _bad("actions must not be empty")
    normalized: list[dict] = []
    for i, raw in enumerate(actions):
        if not isinstance(raw, dict):
            raise _bad(f"actions[{i}] must be an object")
        action_type = raw.get("type")
        if action_type not in ACTION_TYPES:
            raise _bad(f"actions[{i}].type must be one of {sorted(ACTION_TYPES)}")
        action = dict(raw)
        if action_type == "assign":
            if not raw.get("assignee_id"):
                raise _bad(f"actions[{i}].assignee_id is required")
            try:
                uuid.UUID(str(raw["assignee_id"]))
            except ValueError:
                raise _bad(f"actions[{i}].assignee_id must be a UUID")
        elif action_type == "set_priority":
            if raw.get("priority") not in PRIORITIES:
                raise _bad(f"actions[{i}].priority must be one of {sorted(PRIORITIES)}")
        elif action_type == "set_status":
            # Automation rules are ticket-scoped; validate ticket statuses.
            if raw.get("status") not in TICKET_STATUSES:
                raise _bad(f"actions[{i}].status must be one of {sorted(TICKET_STATUSES)}")
        elif action_type == "add_comment":
            if not raw.get("body"):
                raise _bad(f"actions[{i}].body is required")
            action.setdefault("is_internal", True)
        elif action_type == "notify":
            if not raw.get("user_id") or not raw.get("title"):
                raise _bad(f"actions[{i}].user_id and actions[{i}].title are required")
            try:
                uuid.UUID(str(raw["user_id"]))
            except ValueError:
                raise _bad(f"actions[{i}].user_id must be a UUID")
        normalized.append(action)
    return normalized


def create_rule(
    session: Session,
    *,
    org_id: uuid.UUID,
    name: str,
    description: str,
    trigger: str,
    entity_type: str,
    conditions: list[dict],
    actions: list[dict],
    is_enabled: bool,
    created_by_id: uuid.UUID,
) -> AutomationRule:
    if trigger not in AUTOMATION_TRIGGERS:
        raise _bad(f"trigger must be one of {sorted(AUTOMATION_TRIGGERS)}")
    if entity_type not in CONDITION_FIELDS:
        raise _bad(f"entity_type must be one of {sorted(CONDITION_FIELDS)}")
    conditions = validate_conditions(conditions, entity_type)
    actions = validate_actions(actions)
    rule = AutomationRule(
        organization_id=org_id,
        name=name,
        description=description,
        trigger=trigger,
        entity_type=entity_type,
        conditions=conditions,
        actions=actions,
        is_enabled=is_enabled,
        created_by_id=created_by_id,
    )
    session.add(rule)
    session.flush()
    return rule


def update_rule(
    session: Session,
    *,
    rule: AutomationRule,
    name: str | None = None,
    description: str | None = None,
    trigger: str | None = None,
    conditions: list[dict] | None = None,
    actions: list[dict] | None = None,
    is_enabled: bool | None = None,
) -> AutomationRule:
    if trigger is not None:
        if trigger not in AUTOMATION_TRIGGERS:
            raise _bad(f"trigger must be one of {sorted(AUTOMATION_TRIGGERS)}")
        rule.trigger = trigger
    if name is not None:
        rule.name = name
    if description is not None:
        rule.description = description
    if conditions is not None:
        rule.conditions = validate_conditions(conditions, rule.entity_type)
    if actions is not None:
        rule.actions = validate_actions(actions)
    if is_enabled is not None:
        rule.is_enabled = is_enabled
    session.flush()
    return rule


# --- Evaluation ---------------------------------------------------------------


def _condition_matches(actual: object, operator: str, expected: object) -> bool:
    if operator == "eq":
        return str(actual) == str(expected) if actual is not None else expected is None
    if operator == "ne":
        return not _condition_matches(actual, "eq", expected)
    if operator == "in":
        return any(_condition_matches(actual, "eq", v) for v in (expected or []))
    if operator == "not_in":
        return not _condition_matches(actual, "in", expected)
    if operator == "is_null":
        return actual is None
    if operator == "is_not_null":
        return actual is not None
    return False


def _entity_field_value(entity: object, field: str) -> object:
    value = getattr(entity, field, None)
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def conditions_match(entity: object, conditions: list[dict]) -> bool:
    """True only when EVERY condition matches the entity's real values."""
    for condition in conditions:
        actual = _entity_field_value(entity, condition["field"])
        if not _condition_matches(actual, condition["operator"], condition.get("value")):
            return False
    return True


def evaluate_rules(
    session: Session,
    *,
    org_id: uuid.UUID,
    trigger: str,
    entity_type: str,
    entity_id: uuid.UUID,
    actor_id: uuid.UUID | None,
) -> list[AutomationRun]:
    """Evaluate every enabled rule for ``trigger`` against a real entity.

    Returns the ``AutomationRun`` rows created — one per rule that fired.
    Rules that do not match create no row and run nothing. The caller
    commits.
    """
    if trigger not in AUTOMATION_TRIGGERS:
        raise _bad(f"trigger must be one of {sorted(AUTOMATION_TRIGGERS)}")
    entity = load_entity(session, org_id, entity_type, entity_id)

    rules = (
        session.execute(
            select(AutomationRule)
            .where(
                AutomationRule.organization_id == org_id,
                AutomationRule.trigger == trigger,
                AutomationRule.entity_type == entity_type,
                AutomationRule.is_enabled.is_(True),
            )
            .order_by(AutomationRule.created_at)
        )
        .scalars()
        .all()
    )

    runs: list[AutomationRun] = []
    for rule in rules:
        if not conditions_match(entity, list(rule.conditions or [])):
            continue
        applied: list[dict] = []
        error: str | None = None
        for action in rule.actions or []:
            try:
                detail = apply_action(
                    session,
                    org_id=org_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    action=action,
                    actor_id=actor_id,
                )
            except HTTPException as exc:
                detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
                applied.append({"type": action.get("type"), "status": "failed", "error": detail})
                error = detail
                break
            applied.append({**detail, "status": "succeeded"})
        if error is None:
            run_status = "succeeded"
        elif applied and any(a.get("status") == "succeeded" for a in applied):
            run_status = "partial"
        else:
            run_status = "failed"
        run = AutomationRun(
            organization_id=org_id,
            rule_id=rule.id,
            entity_type=entity_type,
            entity_id=entity_id,
            trigger=trigger,
            status=run_status,
            actions_applied=applied,
            error=error,
        )
        session.add(run)
        session.flush()
        runs.append(run)
    return runs
