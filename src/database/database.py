from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlite3 import connect as sqlite_connect
from pathlib import Path
from sqlalchemy.exc import IntegrityError
from os import chmod
import stat
from contextlib import contextmanager
import json
from platform import system

if system() == "Windows":
    from src.config import DATABASE_URL, DATABASE_FILE
else:
    from config import DATABASE_URL, DATABASE_FILE


Base = declarative_base()

class Source(Base):
    __tablename__ = 'source'
    id = Column(Integer, primary_key=True)
    ip = Column(String, nullable=False)
    city = Column(String, nullable=False)
    country = Column(String, nullable=False)
    lat = Column(String, nullable=False)
    lon = Column(String, nullable=False)
    connections = relationship('Connection', back_populates='source')

class Destination(Base):
    __tablename__ = 'destination'
    id = Column(Integer, primary_key=True)
    ip = Column(String, nullable=False)
    city = Column(String, nullable=False)
    country = Column(String, nullable=False)
    lat = Column(String, nullable=False)
    lon = Column(String, nullable=False)
    connections = relationship('Connection', back_populates='destination')

class Connection(Base):
    __tablename__ = 'connections'
    id = Column(Integer, primary_key=True)
    src_id = Column(Integer, ForeignKey('source.id'))
    dst_id = Column(Integer, ForeignKey('destination.id'))
    source = relationship('Source', back_populates='connections')
    destination = relationship('Destination', back_populates='connections')

class Database():
    DB = DATABASE_FILE
    DATABASE_URL = DATABASE_URL
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def __init__(self):
        if not Path(self.DB).exists():
            self.create_database()
        self.conn = sqlite_connect(self.DB)
        self.cursor = self.conn.cursor()
        self.session = self.SessionLocal()

    @contextmanager
    def get_db(self):
        try:
            yield self.session
        finally:
            self.session.close()

    def create_database(self):
        Base.metadata.create_all(bind=self.engine)
        chmod(self.DB, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH)

    def create_table(self, model):
        model.__table__.create(bind=self.engine, checkfirst=True)

    def add_entity(self, entity):
        try:
            self.session.add(entity)
            self.session.commit()
            self.session.refresh(entity)
            return entity
        except IntegrityError:
            self.session.rollback()
            raise
        except Exception as e:
            self.session.rollback()
            raise e
        finally:
            self.session.close()

    def get_entity(self, model, entity_id):
        try:
            return self.session.query(model).filter(model.id == entity_id).first()
        finally:
            self.session.close()

    def close(self):
        self.conn.close()

    def init_db(self):
        if not Path(self.DB).exists():
            print(f"Creating database file: {self.DB} and it's tables")
            self.create_database()
            self.create_table(Source)
            self.create_table(Destination)
            self.close()

    def insert_destinations_from_file(self, file_path, host_src_ip):
        with open(file_path, 'r') as file:
            sources = json.load(file)
        for src in sources:
            destination = Destination(ip=src['ip'], city=src['city'], country=src['country'], lat=src['lat'], lon=src['lon'])
            self.add_entity(destination)
            self.populate_connections(host_src_ip, src['ip'])

    def populate_connections(self, src_ip: str, dst_ip: str):
        with self.get_db() as session:
            src = session.query(Source).filter_by(ip=src_ip).first()
            dst = session.query(Destination).filter_by(ip=dst_ip).first()
            if src and dst:
                connection = Connection(source=src, destination=dst)
                self.add_entity(connection)

    def insert_current_host_as_source(self, host_ip, host_city, host_country, host_lat, host_lon):
        source = Source(ip=host_ip, city=host_city, country=host_country, lat=host_lat, lon=host_lon)
        self.add_entity(source)
