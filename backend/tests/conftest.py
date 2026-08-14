"""Shared test fixtures/helpers for the ipdb test suite."""
from pathlib import Path


def build_lmdb(records, base):
    """测试构库:rebuild 后立即关闭 env,避免同进程双开。"""
    from ipdb._sources._lmdb import rebuild_lmdb
    envs = []
    rebuild_lmdb(records, base, envs.append)
    envs[0].close()
