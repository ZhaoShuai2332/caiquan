#!/usr/bin/env python3
"""
基于承诺-揭示（Commit-Reveal）协议的公平"锤子、剪刀、布"游戏实现

协议说明：
- 使用 SHA-256 作为安全散列函数 H
- 使用密码学安全随机数生成器产生盐值 r（至少 16 字节）
- 出拳编码：0 = 锤子(石头), 1 = 剪刀, 2 = 布
- 拼接格式：m || r

公平性保证：
1. 绑定性：承诺阶段一旦发送 c = H(m||r)，若事后更改 m 或 r，将无法通过验证
2. 隐藏性：若盐值 r 足够随机且足够长，则对手仅凭 c 难以反推出 m
"""

import hashlib
import secrets
import struct
from dataclasses import dataclass
from typing import Tuple, Optional
from enum import IntEnum


class Move(IntEnum):
    """出拳选择"""
    ROCK = 0      # 锤子/石头
    SCISSORS = 1  # 剪刀
    PAPER = 2     # 布
    
    def __str__(self):
        names = {0: "锤子(石头)", 1: "剪刀", 2: "布"}
        return names[self.value]
    
    def beats(self, other: 'Move') -> Optional[bool]:
        """
        判断是否胜过对手
        返回: True=胜, False=负, None=平局
        """
        if self == other:
            return None  # 平局
        # 锤子胜剪刀, 剪刀胜布, 布胜锤子
        winning_combinations = {
            (Move.ROCK, Move.SCISSORS),
            (Move.SCISSORS, Move.PAPER),
            (Move.PAPER, Move.ROCK)
        }
        return (self, other) in winning_combinations


@dataclass
class Commitment:
    """承诺值"""
    hash_value: bytes  # c = H(m || r)
    
    def to_hex(self) -> str:
        return self.hash_value.hex()
    
    @classmethod
    def from_hex(cls, hex_str: str) -> 'Commitment':
        return cls(bytes.fromhex(hex_str))


@dataclass
class Reveal:
    """揭示值"""
    move: Move    # m
    salt: bytes   # r
    
    def to_tuple(self) -> Tuple[int, str]:
        return (self.move.value, self.salt.hex())
    
    @classmethod
    def from_tuple(cls, data: Tuple[int, str]) -> 'Reveal':
        return cls(Move(data[0]), bytes.fromhex(data[1]))


class Player:
    """玩家类，实现承诺-揭示协议"""
    
    SALT_LENGTH = 16  # 盐值长度：16字节 = 128位
    
    def __init__(self, name: str):
        self.name = name
        self._move: Optional[Move] = None
        self._salt: Optional[bytes] = None
        self._commitment: Optional[Commitment] = None
        self._opponent_commitment: Optional[Commitment] = None
    
    @staticmethod
    def _hash(move: Move, salt: bytes) -> bytes:
        """
        计算承诺哈希值 H(m || r)
        使用 SHA-256 作为安全散列函数
        """
        # 将 move 编码为单字节，与 salt 拼接
        data = struct.pack('B', move.value) + salt
        return hashlib.sha256(data).digest()
    
    def commit(self, move: Move) -> Commitment:
        """
        承诺阶段：选择出拳 m，生成随机盐 r，计算并返回承诺 c = H(m || r)
        """
        self._move = move
        # 使用密码学安全的随机数生成器产生盐值
        self._salt = secrets.token_bytes(self.SALT_LENGTH)
        # 计算承诺值
        hash_value = self._hash(self._move, self._salt)
        self._commitment = Commitment(hash_value)
        
        print(f"[{self.name}] 承诺阶段：选择了 {self._move}，生成承诺值")
        return self._commitment
    
    def receive_commitment(self, commitment: Commitment):
        """接收对手的承诺值"""
        self._opponent_commitment = commitment
        print(f"[{self.name}] 收到对手的承诺值: {commitment.to_hex()[:16]}...")
    
    def reveal(self) -> Reveal:
        """
        揭示阶段：返回 (m, r)
        """
        if self._move is None or self._salt is None:
            raise ValueError("尚未进行承诺阶段")
        
        reveal_data = Reveal(self._move, self._salt)
        print(f"[{self.name}] 揭示阶段：公开出拳 {self._move}")
        return reveal_data
    
    def verify(self, reveal: Reveal, expected_commitment: Commitment) -> bool:
        """
        验证对手的揭示值是否与承诺匹配
        验证 H(m || r) == c
        """
        computed_hash = self._hash(reveal.move, reveal.salt)
        is_valid = computed_hash == expected_commitment.hash_value
        
        if is_valid:
            print(f"[{self.name}] 验证成功：对手出拳 {reveal.move} 与承诺匹配")
        else:
            print(f"[{self.name}] ⚠️ 验证失败：对手作弊或通信错误！")
        
        return is_valid


class Game:
    """石头剪刀布游戏，实现完整的承诺-揭示协议流程"""
    
    def __init__(self, alice_name: str = "Alice", bob_name: str = "Bob"):
        self.alice = Player(alice_name)
        self.bob = Player(bob_name)
    
    def play(self, alice_move: Move, bob_move: Move) -> Optional[str]:
        """
        执行一局完整的游戏
        返回胜者名称，平局返回 None
        """
        print("=" * 60)
        print("🎮 公平石头剪刀布游戏开始（基于承诺-揭示协议）")
        print("=" * 60)
        
        # === 阶段 (a): Alice 承诺 ===
        print("\n📝 阶段 (a): Alice 承诺")
        alice_commitment = self.alice.commit(alice_move)
        # Alice 将 c_A 发送给 Bob
        self.bob.receive_commitment(alice_commitment)
        
        # === 阶段 (b): Bob 承诺 ===
        print("\n📝 阶段 (b): Bob 承诺")
        bob_commitment = self.bob.commit(bob_move)
        # Bob 将 c_B 发送给 Alice
        self.alice.receive_commitment(bob_commitment)
        
        # === 阶段 (c): Alice 揭示 ===
        print("\n🔓 阶段 (c): Alice 揭示")
        alice_reveal = self.alice.reveal()
        # Bob 验证 H(m_A || r_A) == c_A
        alice_valid = self.bob.verify(alice_reveal, alice_commitment)
        
        if not alice_valid:
            print(f"\n❌ {self.alice.name} 本局无效（作弊或通信错误）")
            return self.bob.name  # Bob 获胜
        
        # === 阶段 (d): Bob 揭示 ===
        print("\n🔓 阶段 (d): Bob 揭示")
        bob_reveal = self.bob.reveal()
        # Alice 验证 H(m_B || r_B) == c_B
        bob_valid = self.alice.verify(bob_reveal, bob_commitment)
        
        if not bob_valid:
            print(f"\n❌ {self.bob.name} 本局无效（作弊或通信错误）")
            return self.alice.name  # Alice 获胜
        
        # === 阶段 (e): 判定胜负 ===
        print("\n🏆 阶段 (e): 判定胜负")
        print(f"   {self.alice.name}: {alice_reveal.move}")
        print(f"   {self.bob.name}: {bob_reveal.move}")
        
        result = alice_reveal.move.beats(bob_reveal.move)
        
        if result is None:
            print(f"\n🤝 结果：平局！")
            return None
        elif result:
            print(f"\n🎉 结果：{self.alice.name} 获胜！")
            return self.alice.name
        else:
            print(f"\n🎉 结果：{self.bob.name} 获胜！")
            return self.bob.name


class InteractiveGame:
    """交互式游戏模式"""
    
    @staticmethod
    def get_move_input(player_name: str) -> Move:
        """获取玩家的出拳选择"""
        print(f"\n{player_name}，请选择出拳：")
        print("  0 - 锤子(石头)")
        print("  1 - 剪刀")
        print("  2 - 布")
        
        while True:
            try:
                choice = int(input("请输入选择 (0/1/2): "))
                if choice in [0, 1, 2]:
                    return Move(choice)
                print("无效输入，请输入 0、1 或 2")
            except ValueError:
                print("无效输入，请输入数字")
    
    @staticmethod
    def play_interactive():
        """运行交互式游戏"""
        print("\n" + "=" * 60)
        print("欢迎来到公平石头剪刀布游戏！")
        print("本游戏使用承诺-揭示协议，确保公平性")
        print("=" * 60)
        
        game = Game()
        
        # 获取双方出拳（实际网络应用中，这里应该分开进行）
        alice_move = InteractiveGame.get_move_input("Alice")
        bob_move = InteractiveGame.get_move_input("Bob")
        
        # 执行游戏
        game.play(alice_move, bob_move)


def demo():
    """演示程序：展示协议的完整流程"""
    print("\n" + "=" * 60)
    print("📖 演示：承诺-揭示协议的石头剪刀布游戏")
    print("=" * 60)
    
    # 演示 1：正常游戏流程
    print("\n\n【演示 1】正常游戏流程 - Alice 出石头，Bob 出剪刀")
    game1 = Game()
    game1.play(Move.ROCK, Move.SCISSORS)
    
    # 演示 2：平局情况
    print("\n\n【演示 2】平局情况 - 双方都出布")
    game2 = Game()
    game2.play(Move.PAPER, Move.PAPER)
    
    # 演示 3：Bob 获胜
    print("\n\n【演示 3】Bob 获胜 - Alice 出剪刀，Bob 出石头")
    game3 = Game()
    game3.play(Move.SCISSORS, Move.ROCK)
    
    # 演示承诺的绑定性和隐藏性
    print("\n\n" + "=" * 60)
    print("📖 协议安全性说明")
    print("=" * 60)
    print("""
🔐 绑定性 (Binding)：
   承诺阶段一旦发送 c = H(m||r)，若事后更改 m 或 r，
   将无法通过验证等式 H(m||r) = c，
   因此双方无法在看到对方揭示后再改拳。

🔒 隐藏性 (Hiding)：
   若盐值 r 足够随机且足够长（本实现使用 128 位），
   则对手仅凭 c 难以反推出 m，
   从而避免"先手泄露"导致对方针对性出拳。

⏱️ 超时机制（建议）：
   为防止一方承诺后拒绝揭示，可设置超时机制，
   超时则判负或重局并记录信誉。
""")


# 网络通信模拟类（用于展示实际应用场景）
class NetworkSimulator:
    """
    模拟网络通信的承诺-揭示协议
    在实际应用中，这些消息会通过网络传输
    """
    
    def __init__(self):
        self.alice = Player("Alice")
        self.bob = Player("Bob")
        self.messages = []
    
    def log_message(self, sender: str, receiver: str, msg_type: str, content: str):
        """记录网络消息"""
        self.messages.append({
            "from": sender,
            "to": receiver,
            "type": msg_type,
            "content": content
        })
        print(f"  📨 {sender} → {receiver}: [{msg_type}] {content[:32]}...")
    
    def run_protocol(self, alice_move: Move, bob_move: Move):
        """运行完整协议并显示网络消息"""
        print("\n" + "=" * 60)
        print("🌐 网络通信模拟")
        print("=" * 60)
        
        # Step 1: Alice 生成承诺并发送
        print("\n步骤 1: Alice 生成承诺")
        c_a = self.alice.commit(alice_move)
        self.log_message("Alice", "Bob", "COMMITMENT", c_a.to_hex())
        
        # Step 2: Bob 收到承诺后，生成自己的承诺并发送
        print("\n步骤 2: Bob 生成承诺")
        c_b = self.bob.commit(bob_move)
        self.log_message("Bob", "Alice", "COMMITMENT", c_b.to_hex())
        
        # Step 3: Alice 揭示
        print("\n步骤 3: Alice 揭示")
        reveal_a = self.alice.reveal()
        self.log_message("Alice", "Bob", "REVEAL", 
                        f"move={reveal_a.move.value}, salt={reveal_a.salt.hex()}")
        
        # Bob 验证
        if not self.bob.verify(reveal_a, c_a):
            print("❌ Alice 验证失败！")
            return
        
        # Step 4: Bob 揭示
        print("\n步骤 4: Bob 揭示")
        reveal_b = self.bob.reveal()
        self.log_message("Bob", "Alice", "REVEAL",
                        f"move={reveal_b.move.value}, salt={reveal_b.salt.hex()}")
        
        # Alice 验证
        if not self.alice.verify(reveal_b, c_b):
            print("❌ Bob 验证失败！")
            return
        
        # 判定胜负
        print("\n📊 最终结果:")
        print(f"   Alice: {reveal_a.move}")
        print(f"   Bob: {reveal_b.move}")
        result = reveal_a.move.beats(reveal_b.move)
        if result is None:
            print("   结果: 平局")
        elif result:
            print("   结果: Alice 获胜")
        else:
            print("   结果: Bob 获胜")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        # 交互模式
        InteractiveGame.play_interactive()
    elif len(sys.argv) > 1 and sys.argv[1] == "--network":
        # 网络模拟模式
        sim = NetworkSimulator()
        sim.run_protocol(Move.PAPER, Move.ROCK)
    else:
        # 演示模式
        demo()

