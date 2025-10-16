class BasicSS:
    def __init__(self, prime_bits: int = 256):
        """
        初始化安全秘密分享实例

        参数:
        prime_bits: 有限域素数的位数，默认256位
                    决定了可以处理的秘密大小和安全性

        属性:
        - prime: 有限域素数
        - block_size: 最大支持的秘密大小 = (prime_bits - 16) // 8

        实现要求:
        - 生成或使用预定义的大素数p
        - 计算块大小 block_size = (prime_bits - 16) // 8
        """
        pass

def split_secret(self, secret: bytes, n: int, t: int) -> List[Tuple[int, int]]:
    """
    将秘密分割成n个份额，需要至少t个份额才能恢复

    参数:
    secret: 要分享的秘密（字节串）
    n: 生成的份额总数 (2 ≤ t ≤ n ≤ 255)
    t: 恢复秘密所需的最小份额数（阈值）

    返回:
    份额列表 [(share_id, share_value), ...]
    其中 share_id 是份额编号(1到n)，share_value 是份额值

    实现要求:
    - 秘密大小限制为block_size，超过则抛出ValueError
    - 添加2字节长度前缀用于精确恢复
    - 生成t-1次随机多项式，常数项为秘密
    """
    pass

def recover_secret(self, shares: List[Tuple[int, int]]) -> bytes:
    """
    从份额恢复秘密

    参数:
    shares: 份额列表 [(share_id, share_value), ...]

    返回:
    恢复的秘密（字节串）

    实现要求:
    - 使用拉格朗日插值恢复多项式的常数项
    - 从2字节长度前缀中提取原始长度
    """
    pass

def verify_shares_consistency(self, shares: List[Tuple[int, int]], t: int) -> bool:
    """
    验证份额集合的一致性

    参数:
    shares: 要验证的份额列表
    t: 原始阈值

    返回:
    True 如果份额一致（来自同一个多项式），False 否则

    实现要求:
    - 使用拉格朗日插值检查是否能构成t-1次多项式
    - 验证所有份额子集是否恢复相同的值
    """
    pass