import imp
from database import Base,engine
from models import *

Base.metadata.create_all(engine)