# Populates DB with default set of data

import psycopg2
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, ItemCatalog

engine = create_engine('postgresql://catalog:udacity@localhost:5432/catalog')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

category1 = Category(name="Soccer")

session.add(category1)
session.commit()

itemCatalog1 = ItemCatalog(title="Soccer Cleats", description="The shoes",
                           category=category1)

session.add(itemCatalog1)
session.commit()

itemCatalog2 = ItemCatalog(title="Jersey", description="The shirt",
                           category=category1)

session.add(itemCatalog2)
session.commit()

itemCatalog3 = ItemCatalog(title="Shinguards",
                           description="Protects your shins",
                           category=category1)

session.add(itemCatalog3)
session.commit()

category2 = Category(name="Snowboarding")

session.add(category2)
session.commit()

itemCatalog1 = ItemCatalog(title="Snowboard", description="The board",
                           category=category2)

session.add(itemCatalog1)
session.commit()

itemCatalog2 = ItemCatalog(title="Goggles", description="Protects your eyes",
                           category=category2)

session.add(itemCatalog2)
session.commit()

category3 = Category(name="Hockey")

session.add(category3)
session.commit()

itemCatalog1 = ItemCatalog(title="Stick", description="The stick for hocky",
                           category=category3)

session.add(itemCatalog1)
session.commit()

category4 = Category(name="Basseball")

session.add(category4)
session.commit()

itemCatalog1 = ItemCatalog(title="Bat", description="Useful in baseball",
                           category=category4)

session.add(itemCatalog1)
session.commit()

category5 = Category(name="Frisbee")

session.add(category5)
session.commit()

category6 = Category(name="Basketball")

session.add(category6)
session.commit()

category7 = Category(name="Rock Climbing")

session.add(category7)
session.commit()

category8 = Category(name="Foosball")

session.add(category8)
session.commit()

category9 = Category(name="Skating")

session.add(category9)
session.commit()

print("added menu items!")
