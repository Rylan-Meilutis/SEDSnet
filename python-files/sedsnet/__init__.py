from . import sedsnet as sedsnet
from .sedsnet import *  # noqa: F403,F401

__doc__ = sedsnet.__doc__
if hasattr(sedsnet, "__all__"):
    __all__ = sedsnet.__all__
