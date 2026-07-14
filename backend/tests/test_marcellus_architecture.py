import pytest
from httpx import AsyncClient

from main import app


@pytest.mark.asyncio
async def test_architecture_exposes_all_core_concepts(client: AsyncClient):
    response = await client.get("/api/v1/marcellus/architecture")

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "Marcellus Plexus Architecture"
    assert payload["working_name"] is True
    assert len(payload["hearts"]) == 3
    assert len(payload["arms"]) == 8
    assert len(payload["capability_nodes"]) == 26
    assert payload["terminology"]["reflexes"]
    assert payload["terminology"]["plexus"]
    assert payload["terminology"]["regeneration"]
    assert payload["reflexes"]["implementation_state"] == "existing"
    assert payload["plexus"]["implementation_state"] == "existing"
    assert payload["regeneration"]["implementation_state"] == "partial"
    assert all(node["plexus_ready"] for node in payload["capability_nodes"])


@pytest.mark.asyncio
async def test_every_capability_node_has_one_arm_and_real_legacy_task_route(client: AsyncClient):
    response = await client.get("/api/v1/marcellus/architecture")
    payload = response.json()
    nodes = payload["capability_nodes"]
    arm_node_ids = [node_id for arm in payload["arms"] for node_id in arm["node_ids"]]

    assert len(arm_node_ids) == len(set(arm_node_ids)) == len(nodes)
    assert set(arm_node_ids) == {node["id"] for node in nodes}

    openapi_paths = app.openapi()["paths"]
    for node in nodes:
        assert node["task_route"] in openapi_paths
        assert "post" in openapi_paths[node["task_route"]]


@pytest.mark.asyncio
async def test_capability_nodes_can_be_filtered_by_arm(client: AsyncClient):
    response = await client.get(
        "/api/v1/marcellus/nodes",
        params={"arm_id": "cloud_infrastructure"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert {node["id"] for node in payload} == {
        "cloud-security",
        "configuration-security",
        "terraform-governance",
    }
    assert all(node["arm_id"] == "cloud_infrastructure" for node in payload)


@pytest.mark.asyncio
async def test_unknown_capability_node_is_not_disclosed(client: AsyncClient):
    response = await client.get("/api/v1/marcellus/nodes/not-a-node")

    assert response.status_code == 404
    assert response.json() == {"detail": "Capability Node not found"}
