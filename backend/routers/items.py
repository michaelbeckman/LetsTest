from fastapi import APIRouter, HTTPException, status
from typing import List

from backend.models import Item, ItemCreate, ItemUpdate

router = APIRouter(prefix="/items", tags=["items"])

# In-memory store (replace with a real DB in production)
_items: dict[int, Item] = {}
_next_id: int = 1


@router.get("/", response_model=List[Item])
def list_items():
    """Return all items."""
    return list(_items.values())


@router.post("/", response_model=Item, status_code=status.HTTP_201_CREATED)
def create_item(payload: ItemCreate):
    """Create a new item."""
    global _next_id
    item = Item(id=_next_id, **payload.model_dump())
    _items[_next_id] = item
    _next_id += 1
    return item


@router.get("/{item_id}", response_model=Item)
def get_item(item_id: int):
    """Retrieve an item by ID."""
    item = _items.get(item_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    return item


@router.patch("/{item_id}", response_model=Item)
def update_item(item_id: int, payload: ItemUpdate):
    """Partially update an item."""
    item = _items.get(item_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    updated = item.model_copy(update=payload.model_dump(exclude_unset=True))
    _items[item_id] = updated
    return updated


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(item_id: int):
    """Delete an item by ID."""
    if item_id not in _items:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    del _items[item_id]
