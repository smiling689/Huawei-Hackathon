class ProactiveSecretSharing:
    def __init__(self, refresh_interval: int = 30*24*3600,
                 prime_bits: int = 256,
                 prime: Optional[int] = None):
        """
        初始化主动秘密分享系统

        参数:
        refresh_interval: 刷新间隔（秒），默认30天
        prime_bits: 素数位数（默认256位）
        prime: 使用的素数（可选）

        实现要求:
        - 初始化epoch计数器
        - 设置刷新定时器
        """
        pass

def active_refresh(self, old_shares: List[Tuple[int, int]],
                   n: int, t: int) -> List[Tuple[int, int]]:
    """
    执行份额刷新（保持秘密不变）

    参数:
    old_shares: 旧份额列表
    n: 份额总数
    t: 阈值

    返回:
    刷新后的新份额列表

    实现要求:
    - 生成零多项式 δ(x) 满足 δ(0) = 0
    - 新份额 = 旧份额 + δ(share_id)
    - 递增epoch号
    """
    pass

def schedule_automatic_refresh(self) -> bool:
    """
    检查是否需要自动刷新

    返回:
    True 如果到达刷新时间，False 否则

    实现要求:
    - 基于refresh_interval和last_refresh_time判断
    """
    pass

def generate_refresh_polynomial(self, participant_id: int,
                                n: int, t: int) -> Dict:
    """
    为参与者生成刷新多项式

    参数:
    participant_id: 参与者ID
    n: 总参与者数
    t: 阈值

    返回:
    {
        'polynomial': [0, a_1, a_2, ..., a_{t-1}],
        'shares': [(id, value), ...],
        'epoch': int
    }

    实现要求:
    - 多项式常数项必须为0
    - 为所有参与者计算刷新份额
    """
    pass