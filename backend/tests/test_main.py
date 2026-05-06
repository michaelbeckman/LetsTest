import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.routers import items as items_router


@pytest.fixture(autouse=True)
def reset_store():
    """Reset the in-memory store before each test."""
    items_router._items.clear()
    items_router._next_id = 1
    yield


client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_item():
    payload = {"name": "Widget", "price": 9.99}
    response = client.post("/items/", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["id"] == 1
    assert data["name"] == "Widget"
    assert data["price"] == 9.99
    assert data["in_stock"] is True


def test_list_items():
    client.post("/items/", json={"name": "A", "price": 1.0})
    client.post("/items/", json={"name": "B", "price": 2.0})
    response = client.get("/items/")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_get_item():
    client.post("/items/", json={"name": "Widget", "price": 9.99})
    response = client.get("/items/1")
    assert response.status_code == 200
    assert response.json()["name"] == "Widget"


def test_get_item_not_found():
    response = client.get("/items/999")
    assert response.status_code == 404


def test_update_item():
    client.post("/items/", json={"name": "Widget", "price": 9.99})
    response = client.patch("/items/1", json={"price": 4.99, "in_stock": False})
    assert response.status_code == 200
    data = response.json()
    assert data["price"] == 4.99
    assert data["in_stock"] is False
    assert data["name"] == "Widget"  # unchanged


def test_update_item_not_found():
    response = client.patch("/items/999", json={"price": 1.0})
    assert response.status_code == 404


def test_delete_item():
    client.post("/items/", json={"name": "Widget", "price": 9.99})
    response = client.delete("/items/1")
    assert response.status_code == 204
    assert client.get("/items/1").status_code == 404


def test_delete_item_not_found():
    response = client.delete("/items/999")
    assert response.status_code == 404


def test_create_item_invalid_price():
    response = client.post("/items/", json={"name": "Bad", "price": -1.0})
    assert response.status_code == 422


def test_create_item_missing_name():
    response = client.post("/items/", json={"price": 5.0})
    assert response.status_code == 422


def test_create_item_with_description():
    payload = {"name": "Gadget", "price": 19.99, "description": "A handy gadget"}
    response = client.post("/items/", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["description"] == "A handy gadget"
