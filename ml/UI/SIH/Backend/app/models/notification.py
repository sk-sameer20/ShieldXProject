"""
SQLAlchemy 2.0 Model for Operator Notifications
"""
from typing import Optional
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base, TimestampMixin


class Notification(Base, TimestampMixin):
    """
    Operator notification bell items triggered by high-severity alerts.
    """
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("alerts.alert_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="critical")
    time_label: Mapped[str] = mapped_column(String(32), nullable=False, default="just now")
    is_cleared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
