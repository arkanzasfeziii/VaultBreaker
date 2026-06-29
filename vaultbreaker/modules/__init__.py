"""Database attack modules."""
from vaultbreaker.modules.sqli import SQLiModule
from vaultbreaker.modules.mongo import MongoModule
from vaultbreaker.modules.redis import RedisModule
from vaultbreaker.modules.elastic import ElasticModule
from vaultbreaker.modules.credextract import CredExtractModule
from vaultbreaker.modules.exfil import ExfilModule
__all__ = ["SQLiModule","MongoModule","RedisModule","ElasticModule","CredExtractModule","ExfilModule"]
