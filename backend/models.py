from pydantic import BaseModel, Field
from typing import Optional


class ItemBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Name of the item")
    description: Optional[str] = Field(None, max_length=500, description="Optional item description")
    price: float = Field(..., gt=0, description="Price must be greater than zero")
    in_stock: bool = Field(default=True, description="Whether the item is in stock")


class ItemCreate(ItemBase):
    pass


class ItemUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    price: Optional[float] = Field(None, gt=0)
    in_stock: Optional[bool] = None


class Item(ItemBase):
    id: int

    model_config = {"from_attributes": True}
