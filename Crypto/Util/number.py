import secrets
from sympy import nextprime


def getPrime(bits: int) -> int:
    """
    生成指定位数的素数，作为 PyCryptodome number.getPrime 的轻量替代。

    仅用于缺失 PyCryptodome 依赖时的兼容，安全性取决于 sympy 的素数生成。
    """
    if bits <= 1:
        raise ValueError("bits 必须大于 1")
    candidate = secrets.randbits(bits - 1)
    candidate |= 1 << (bits - 1)
    candidate |= 1
    return nextprime(candidate)
