from sqlmodel import Field, Relationship, SQLModel


class User(SQLModel, table=True):
    username: str = Field(primary_key=True)
    full_name: str
    email: str
    disabled: bool | None = None
    hashed_password: str
    token: str | None = None
    decks: list["Deck"] = Relationship(back_populates="user")

class Deck(SQLModel, table=True):
    deck_id: str = Field(primary_key=True)
    username: str = Field(foreign_key="user.username")
    user: User = Relationship(back_populates="decks")