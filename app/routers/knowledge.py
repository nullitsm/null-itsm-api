"""Knowledge base — Phase 2 ITSM engine.

Articles move draft -> published -> archived. Drafts are visible
only to callers holding knowledge:create or knowledge:manage; a
published article's view_count increments on every GET. Feedback
(helpful / comment) is append-only.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.deps import Principal, get_db, require_permission
from app.models.itsm import KnowledgeArticle, KnowledgeFeedback
from app.services.itsm_service import get_org_row

router = APIRouter(prefix="/api/v1/knowledge", tags=["knowledge"])

ARTICLE_STATUSES = {"draft", "published", "archived"}


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "article"


class ArticleCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    slug: str | None = Field(default=None, max_length=255)
    body: str = ""
    category: str = "General"
    tags: list[str] = []


class ArticleUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    slug: str | None = Field(default=None, max_length=255)
    body: str | None = None
    status: str | None = None
    category: str | None = Field(default=None, max_length=100)
    tags: list[str] | None = None


class ArticleOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    slug: str
    body: str
    status: str
    author_id: uuid.UUID | None
    category: str
    tags: list
    view_count: int
    published_at: datetime | None
    created_at: datetime
    updated_at: datetime


class FeedbackCreate(BaseModel):
    helpful: bool
    comment: str | None = None


class FeedbackOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    article_id: uuid.UUID
    user_id: uuid.UUID | None
    helpful: bool
    comment: str | None
    created_at: datetime


def _out(a: KnowledgeArticle) -> ArticleOut:
    return ArticleOut(
        id=a.id,
        organization_id=a.organization_id,
        title=a.title,
        slug=a.slug,
        body=a.body,
        status=a.status,
        author_id=a.author_id,
        category=a.category,
        tags=a.tags or [],
        view_count=a.view_count,
        published_at=a.published_at,
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


def _feedback_out(f: KnowledgeFeedback) -> FeedbackOut:
    return FeedbackOut(
        id=f.id,
        organization_id=f.organization_id,
        article_id=f.article_id,
        user_id=f.user_id,
        helpful=f.helpful,
        comment=f.comment,
        created_at=f.created_at,
    )


def _can_see_drafts(principal: Principal) -> bool:
    return principal.has("knowledge:create") or principal.has("knowledge:manage")


def _check_slug_unique(session: Session, principal: Principal, slug: str, exclude_id: uuid.UUID | None = None) -> None:
    clash = session.execute(
        select(KnowledgeArticle).where(
            KnowledgeArticle.organization_id == principal.organization_id, KnowledgeArticle.slug == slug
        )
    ).scalar_one_or_none()
    if clash is not None and clash.id != exclude_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Slug already in use in this organization")


@router.get("/articles", response_model=list[ArticleOut])
def list_articles(
    session: Session = Depends(get_db), principal: Principal = Depends(require_permission("knowledge:read"))
):
    query = select(KnowledgeArticle).where(KnowledgeArticle.organization_id == principal.organization_id)
    if not _can_see_drafts(principal):
        query = query.where(KnowledgeArticle.status == "published")
    rows = session.execute(query.order_by(KnowledgeArticle.created_at.desc())).scalars()
    return [_out(a) for a in rows]


@router.post("/articles", response_model=ArticleOut, status_code=status.HTTP_201_CREATED)
def create_article(
    body: ArticleCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("knowledge:create")),
):
    slug = _slugify(body.slug) if body.slug else _slugify(body.title)
    _check_slug_unique(session, principal, slug)
    article = KnowledgeArticle(
        organization_id=principal.organization_id,
        title=body.title,
        slug=slug,
        body=body.body,
        category=body.category,
        tags=body.tags or [],
        author_id=principal.user_id,
        status="draft",
    )
    session.add(article)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.KB_ARTICLE_CREATED,
        resource_type="knowledge_article",
        resource_id=str(article.id),
        outcome="success",
        metadata={"slug": article.slug},
    )
    out = _out(article)
    session.commit()
    return out


@router.get("/articles/{article_id}", response_model=ArticleOut)
def get_article(
    article_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("knowledge:read")),
):
    article = get_org_row(session, KnowledgeArticle, article_id, principal.organization_id)
    if article.status != "published" and not _can_see_drafts(principal):
        # Drafts (and archived articles) are invisible to plain readers.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if article.status == "published":
        article.view_count += 1
        session.flush()
    out = _out(article)
    session.commit()
    return out


@router.patch("/articles/{article_id}", response_model=ArticleOut)
def update_article(
    article_id: uuid.UUID,
    body: ArticleUpdate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("knowledge:manage")),
):
    article = get_org_row(session, KnowledgeArticle, article_id, principal.organization_id)
    if body.status is not None:
        if body.status not in ARTICLE_STATUSES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status")
        article.status = body.status
        if body.status == "published" and article.published_at is None:
            article.published_at = datetime.now(timezone.utc)
    if body.title is not None:
        article.title = body.title
    if body.slug is not None:
        slug = _slugify(body.slug)
        _check_slug_unique(session, principal, slug, exclude_id=article.id)
        article.slug = slug
    if body.body is not None:
        article.body = body.body
    if body.category is not None:
        article.category = body.category
    if body.tags is not None:
        article.tags = body.tags
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.KB_ARTICLE_UPDATED,
        resource_type="knowledge_article",
        resource_id=str(article.id),
        outcome="success",
        metadata={"status": article.status},
    )
    session.flush()
    out = _out(article)
    session.commit()
    return out


@router.delete("/articles/{article_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_article(
    article_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("knowledge:manage")),
):
    article = get_org_row(session, KnowledgeArticle, article_id, principal.organization_id)
    session.delete(article)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.KB_ARTICLE_UPDATED,
        resource_type="knowledge_article",
        resource_id=str(article.id),
        outcome="success",
        metadata={"deleted": True},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/articles/{article_id}/publish", response_model=ArticleOut)
def publish_article(
    article_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("knowledge:publish")),
):
    article = get_org_row(session, KnowledgeArticle, article_id, principal.organization_id)
    if article.status == "published":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Article is already published")
    article.status = "published"
    article.published_at = datetime.now(timezone.utc)
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.KB_ARTICLE_PUBLISHED,
        resource_type="knowledge_article",
        resource_id=str(article.id),
        outcome="success",
        metadata={"slug": article.slug},
    )
    session.flush()
    out = _out(article)
    session.commit()
    return out


@router.post("/articles/{article_id}/feedback", response_model=FeedbackOut, status_code=status.HTTP_201_CREATED)
def create_feedback(
    article_id: uuid.UUID,
    body: FeedbackCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("knowledge:read")),
):
    article = get_org_row(session, KnowledgeArticle, article_id, principal.organization_id)
    if article.status != "published" and not _can_see_drafts(principal):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    feedback = KnowledgeFeedback(
        organization_id=principal.organization_id,
        article_id=article.id,
        user_id=principal.user_id,
        helpful=body.helpful,
        comment=body.comment,
    )
    session.add(feedback)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        action=audit_mod.KB_FEEDBACK_CREATED,
        resource_type="knowledge_article",
        resource_id=str(article.id),
        outcome="success",
        metadata={"helpful": body.helpful},
    )
    out = _feedback_out(feedback)
    session.commit()
    return out


@router.get("/articles/{article_id}/feedback", response_model=list[FeedbackOut])
def list_feedback(
    article_id: uuid.UUID,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("knowledge:read")),
):
    article = get_org_row(session, KnowledgeArticle, article_id, principal.organization_id)
    if article.status != "published" and not _can_see_drafts(principal):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    rows = session.execute(
        select(KnowledgeFeedback)
        .where(KnowledgeFeedback.article_id == article.id)
        .order_by(KnowledgeFeedback.created_at.desc())
    ).scalars()
    return [_feedback_out(f) for f in rows]
