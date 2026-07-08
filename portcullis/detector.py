
from datetime import datetime, timedelta
from enum import IntEnum
from dataclasses import dataclass
from collections import defaultdict, deque
from portcullis.parser import EventType

class Level(IntEnum):
    ALERT = 1
    RATE_LIMIT = 2
    BLOCK = 3

@dataclass
class Detection:
    ip: str
    level: Level
    weighted_count: float
    usernames: frozenset
    first_seen: datetime
    last_seen: datetime

FAILURE_WEIGHTS = {
    EventType.FAILED_PASSWORD: 1.0,
    EventType.INVALID_USER: 2.0,
    EventType.AUTH_MAX_EXCEEDED: 2.0,
}

class BruteForceDetector:
    
    def __init__(self, alert_threshold=3.0, rate_limit_threshold=5.0, block_threshold=8.0, window_seconds=600, invalid_user_weight=2.0, distinct_users_threshold=4):
        self.alert_threshold = alert_threshold
        self.rate_limit_threshold = rate_limit_threshold
        self.block_threshold = block_threshold
        self.window_seconds = window_seconds
        self.distinct_users_threshold = distinct_users_threshold

        self.weights = dict(FAILURE_WEIGHTS)
        self.weights[EventType.INVALID_USER] = invalid_user_weight

        self._failures = defaultdict(deque)
        self._reported = {}
    
    def process_event(self, event) -> Detection | None: 
       
        weight = self.weights.get(event.event_type)
        if weight is None or event.source_ip is None:
            return None
       
        ip = event.source_ip
        window = self._failures[ip]
        window.append((event.timestamp, weight, event.username))

        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        while window and window[0][0] < cutoff:
           window.popleft()
        
        if len(window) == 1 and ip in self._reported:
           del self._reported[ip]
        
        total = sum(w for _, w, _ in window)
        usernames = {u for _, _, u in window if u is not None}
        level = None
        if total >= self.block_threshold:
            level = Level.BLOCK
        elif total >= self.rate_limit_threshold:
            level = Level.RATE_LIMIT
        elif total >= self.alert_threshold:
            level = Level.ALERT
        
        if len(usernames) >= self.distinct_users_threshold:
            if level is None or level < Level.RATE_LIMIT:
                level = Level.RATE_LIMIT
        
        if level is None:
            return None
        
        already = self._reported.get(ip)
        if already is not None and level <= already:
            return None
        self._reported[ip] = level

        return Detection(
            ip=ip,
            level=level,
            weighted_count=total,
            usernames=frozenset(usernames),
            first_seen=window[0][0],
            last_seen=window[-1][0],
        )
