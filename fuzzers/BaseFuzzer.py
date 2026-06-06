from abc import ABC, abstractmethod

class BaseFuzzer(ABC):
    """
    Base class for all fuzzers. Defines the interface for fuzzers.
    """
    def __init__(self, target_mac, client_mac, interface):
        self.client_mac = client_mac
        self.target_mac = target_mac
        self.interface = interface
    
    @abstractmethod
    def setup(self):
        pass
    
    @abstractmethod
    def next_frame(self):
        pass