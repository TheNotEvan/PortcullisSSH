import json
import os
import time

class LogMonitor:
    
    def __init__(self, log_path, state_path = None,start_at_end=True, poll_interval=1.0):
        self.log_path = log_path
        self.state_path = state_path
        self.offset = 0
        self.poll_interval = poll_interval
        self._file = None
        self._inode = None

        if start_at_end:
            try:
                self.offset = os.path.getsize(log_path)
            except FileNotFoundError:
                self.offset = 0

        self._load_state()

    def _load_state(self):
        if self.state_path is None:
            return

        try:
            with open(self.state_path, 'r') as f:
                state = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return 
        if(state.get('log_path') != self.log_path):
            return
        
        saved_inode = state.get("inode")

        if saved_inode is None:
            return
        
        try:
            current_inode = os.stat(self.log_path).st_ino
        except FileNotFoundError:
            self.offset = 0
            return 

        if saved_inode != current_inode:
            self.offset = 0
            return
        self.offset = state["offset"]
        

    def _save_state(self):
        if self.state_path is None:
            return
        state = {
            "log_path": self.log_path,
            "offset": self.offset,
            "inode": self._inode,
        }
        tmp = self.state_path + ".tmp"
        with open(tmp, 'w') as f:
            json.dump(state, f)
        os.replace(tmp, self.state_path)


    def _read_from_handle(self):
        if self._file is None:
            try:
                self._file = open(self.log_path, 'rb')
            except FileNotFoundError:
                return []
            inode = os.fstat(self._file.fileno()).st_ino
            if self._inode is not None and inode != self._inode:
                self.offset = 0
            self._inode = inode
            self._file.seek(self.offset)

        lines = []

        for raw in self._file:
            if not raw.endswith(b"\n"):
                self._file.seek(-len(raw), 1)
                break
            lines.append(raw.decode('utf-8', errors='replace'))
        return lines

    def read_new_lines(self):

        lines = self._read_from_handle()

        try:
            st = os.stat(self.log_path)
        except FileNotFoundError:
            st = None   

        if st is not None and self._file is not None:
            if st.st_ino != self._inode:
                self.close()
                self.offset = 0
                lines += self._read_from_handle()
            elif st.st_size < self._file.tell():
                self._file.seek(0)
                self.offset = 0
                lines += self._read_from_handle()

        if self._file is not None:
            new_offset = self._file.tell()
            if new_offset != self.offset:
                self.offset = new_offset
                self._save_state()
        return lines

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None

    def follow(self):
        while True:
            lines = self.read_new_lines()
            if lines:
                for line in lines:
                    yield line
            else:
                time.sleep(self.poll_interval)