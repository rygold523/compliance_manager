from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api import access_reviews


def payload():
    return access_reviews.CampaignCreate(
        name="Q3 Access Review",
        reviewer="Compliance Owner",
        due_date="2099-09-30",
        scope_note="Quarterly certification",
        items=[
            access_reviews.ReviewItemInput(
                subject_type="dashboard_user",
                username="auditor",
                system="Compliance Dashboard",
                access="Role: auditor",
                privileged=False,
            )
        ],
    )


def test_campaign_lifecycle_and_completion_lock(monkeypatch, tmp_path):
    monkeypatch.setattr(access_reviews, "STORE_FILE", tmp_path / "reviews.json")
    monkeypatch.setattr(access_reviews, "write_changelog", lambda *args, **kwargs: None)
    admin = SimpleNamespace(username="dashboard.admin")

    campaign = access_reviews.create_campaign(payload(), admin)["campaign"]
    item = campaign["items"][0]
    assert item["decision"] == "pending"

    with pytest.raises(HTTPException) as incomplete:
        access_reviews.complete_campaign(campaign["campaign_id"], admin)
    assert incomplete.value.status_code == 409

    access_reviews.decide_item(
        campaign["campaign_id"],
        item["item_id"],
        access_reviews.ItemDecision(decision="retain", comment="Required"),
        admin,
    )
    completed = access_reviews.complete_campaign(campaign["campaign_id"], admin)["campaign"]
    assert completed["status"] == "completed"

    with pytest.raises(HTTPException) as locked:
        access_reviews.decide_item(
            campaign["campaign_id"],
            item["item_id"],
            access_reviews.ItemDecision(decision="remove"),
            admin,
        )
    assert locked.value.status_code == 409


def test_csv_formula_values_are_neutralized():
    assert access_reviews._csv_safe("=cmd") == "'=cmd"
    assert access_reviews._csv_safe("normal") == "normal"


def test_access_review_routes_registered():
    paths = {route.path for route in access_reviews.router.routes}
    assert "/api/access-reviews" in paths
    assert "/api/access-reviews/{campaign_id}" in paths
    assert "/api/access-reviews/{campaign_id}/items/{item_id}" in paths
    assert "/api/access-reviews/{campaign_id}/complete" in paths
    assert "/api/access-reviews/{campaign_id}/archive" in paths
    assert "/api/access-reviews/{campaign_id}/export" in paths
