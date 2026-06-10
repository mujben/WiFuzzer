from abc import ABC, abstractmethod

class BaseFuzzer(ABC):
    """
    Base class for all fuzzers. Defines the interface for fuzzers.
    """
    def __init__(self, target_mac, client_mac=None, interface=None):
        self.client_mac = client_mac.lower() if client_mac else None
        self.target_mac = target_mac.lower() if target_mac else None
        self.interface = interface
    
    @abstractmethod
    def setup(self):
        pass
    
    @abstractmethod
    def next_frame(self):
        pass
        
    @abstractmethod
    def is_exhausted(self) -> bool:
        pass