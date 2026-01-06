"""
基于承诺-揭示（Commit-Reveal）协议的公平"锤子、剪刀、布"游戏

协议流程：
    设双方为 Alice 与 Bob，出拳集合 M = {锤子, 剪刀, 布}，
    取安全散列函数 H(·)（如 SHA-256）。

    (a) Alice 承诺：Alice 选 m_A ∈ M，生成随机盐 r_A（128 bit），
        计算承诺 c_A = H(m_A || r_A)，并将 c_A 发送给 Bob。

    (b) Bob 承诺：Bob 选 m_B ∈ M，生成随机盐 r_B，
        计算 c_B = H(m_B || r_B)，并将 c_B 发送给 Alice。

    (c) Alice 揭示：Alice 发送 (m_A, r_A) 给 Bob，
        Bob 验证 H(m_A || r_A) = c_A，若不相等则判定 Alice 本局无效。

    (d) Bob 揭示：Bob 发送 (m_B, r_B) 给 Alice，
        Alice 验证 H(m_B || r_B) = c_B，若不相等则判定 Bob 本局无效。

    (e) 判定胜负：双方依据公开规则比较 m_A 与 m_B 得到结果。

公平性说明：
    (1) 绑定性：承诺阶段一旦发送 c = H(m||r)，若事后更改 m 或 r，
        将无法通过验证等式 H(m||r) = c，消除"后手吃亏/占便宜"的问题。
    (2) 隐藏性：若盐 r 足够随机且足够长，则对手仅凭 c 难以反推出 m，
        从而避免"先手泄露"导致对方针对性出拳。

实现建议：
    - 程序中用安全散列（SHA-256）实现 H
    - 用密码学安全随机数生成器产生盐 r（至少 16 字节）
    - 规定出拳编码（如用 0, 1, 2 表示锤子/剪刀/布）与拼接格式（固定为 m||r）
"""

import hashlib
import secrets
import struct
from typing import Tuple, Optional


# =============================================================================
# 常量定义
# =============================================================================

ROCK = 0      # 锤子（石头）
SCISSORS = 1  # 剪刀
PAPER = 2     # 布

MOVE_NAMES = {ROCK: "锤子", SCISSORS: "剪刀", PAPER: "布"}
SALT_LENGTH = 16  # 盐值长度：16 字节 = 128 bit


# =============================================================================
# 核心函数
# =============================================================================

def compute_hash(move: int, salt: bytes) -> bytes:
    """
    计算承诺哈希值 H(m || r)
    
    Args:
        move: 出拳选择 (0=锤子, 1=剪刀, 2=布)
        salt: 随机盐值 r
    
    Returns:
        SHA-256 哈希值
    """
    data = struct.pack('B', move) + salt  # m || r
    return hashlib.sha256(data).digest()


def generate_commitment(move: int) -> Tuple[bytes, bytes]:
    """
    承诺阶段：生成承诺值 c = H(m || r)
    
    Args:
        move: 出拳选择
    
    Returns:
        (commitment, salt): 承诺值和盐值的元组
    """
    salt = secrets.token_bytes(SALT_LENGTH)
    commitment = compute_hash(move, salt)
    return commitment, salt


def verify_commitment(move: int, salt: bytes, commitment: bytes) -> bool:
    """
    验证揭示值是否与承诺匹配：H(m || r) == c
    
    Args:
        move: 揭示的出拳
        salt: 揭示的盐值
        commitment: 之前收到的承诺值
    
    Returns:
        验证是否通过
    """
    return compute_hash(move, salt) == commitment


def judge(move_a: int, move_b: int) -> Optional[str]:
    """
    判定胜负
    
    Args:
        move_a: Alice 的出拳
        move_b: Bob 的出拳
    
    Returns:
        "Alice" / "Bob" / None (平局)
    """
    if move_a == move_b:
        return None  # 平局
    
    # 锤子胜剪刀，剪刀胜布，布胜锤子
    if (move_a - move_b) % 3 == 2:
        return "Alice"
    else:
        return "Bob"


# =============================================================================
# 协议执行
# =============================================================================

def run_protocol(alice_move: int, bob_move: int) -> Optional[str]:
    """
    执行完整的承诺-揭示协议
    
    Args:
        alice_move: Alice 的出拳选择
        bob_move: Bob 的出拳选择
    
    Returns:
        胜者名称，平局返回 None
    """
    print("=" * 50)
    print("承诺-揭示协议：公平石头剪刀布游戏")
    print("=" * 50)
    
    # (a) Alice 承诺
    print("\n(a) Alice 承诺阶段")
    c_A, r_A = generate_commitment(alice_move)
    print(f"    m_A = {alice_move} ({MOVE_NAMES[alice_move]})")
    print(f"    r_A = {r_A.hex()}")
    print(f"    c_A = H(m_A || r_A) = {c_A.hex()[:32]}...")
    print(f"    [Alice -> Bob] 发送 c_A")
    
    # (b) Bob 承诺
    print("\n(b) Bob 承诺阶段")
    c_B, r_B = generate_commitment(bob_move)
    print(f"    m_B = {bob_move} ({MOVE_NAMES[bob_move]})")
    print(f"    r_B = {r_B.hex()}")
    print(f"    c_B = H(m_B || r_B) = {c_B.hex()[:32]}...")
    print(f"    [Bob -> Alice] 发送 c_B")
    
    # (c) Alice 揭示
    print("\n(c) Alice 揭示阶段")
    print(f"    [Alice -> Bob] 发送 (m_A={alice_move}, r_A)")
    if verify_commitment(alice_move, r_A, c_A):
        print(f"    [Bob 验证] H(m_A || r_A) = c_A ✓")
    else:
        print(f"    [Bob 验证] 失败！Alice 本局无效")
        return "Bob"
    
    # (d) Bob 揭示
    print("\n(d) Bob 揭示阶段")
    print(f"    [Bob -> Alice] 发送 (m_B={bob_move}, r_B)")
    if verify_commitment(bob_move, r_B, c_B):
        print(f"    [Alice 验证] H(m_B || r_B) = c_B ✓")
    else:
        print(f"    [Alice 验证] 失败！Bob 本局无效")
        return "Alice"
    
    # (e) 判定胜负
    print("\n(e) 判定胜负")
    print(f"    Alice: {MOVE_NAMES[alice_move]}")
    print(f"    Bob:   {MOVE_NAMES[bob_move]}")
    
    winner = judge(alice_move, bob_move)
    if winner is None:
        print(f"    结果: 平局")
    else:
        print(f"    结果: {winner} 获胜")
    
    return winner


# =============================================================================
# 主程序
# =============================================================================

if __name__ == "__main__":
    # 测试用例 1：Alice 出锤子，Bob 出剪刀 -> Alice 胜
    print("\n【测试 1】Alice=锤子, Bob=剪刀")
    run_protocol(ROCK, SCISSORS)
    
    # 测试用例 2：Alice 出剪刀，Bob 出布 -> Alice 胜
    print("\n\n【测试 2】Alice=剪刀, Bob=布")
    run_protocol(SCISSORS, PAPER)
    
    # 测试用例 3：Alice 出布，Bob 出锤子 -> Alice 胜
    print("\n\n【测试 3】Alice=布, Bob=锤子")
    run_protocol(PAPER, ROCK)
    
    # 测试用例 4：平局
    print("\n\n【测试 4】Alice=剪刀, Bob=剪刀 (平局)")
    run_protocol(SCISSORS, SCISSORS)
    
    # 测试用例 5：Bob 获胜
    print("\n\n【测试 5】Alice=布, Bob=剪刀")
    run_protocol(PAPER, SCISSORS)

