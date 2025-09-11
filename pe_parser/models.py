class section_header:
    def __init__(self, Name, PhysicalAddress, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers, Characteristics):
        self.Name = Name
        self.PhysicalAddress = PhysicalAddress
        self.VirtualSize = VirtualSize
        self.VirtualAddress = VirtualAddress
        self.SizeOfRawData = SizeOfRawData
        self.PointerToRawData = PointerToRawData
        self.PointerToRelocations = PointerToRelocations
        self.PointerToLinenumbers = PointerToLinenumbers
        self.NumberOfRelocations = NumberOfRelocations
        self.NumberOfLinenumbers = NumberOfLinenumbers
        self.Characteristics = Characteristics

class image_import_descriptor:
    def __init__(self, Characteristics = 0, OriginalFirstThunk = 0, TimeDateStamp = 0, ForwarderChain = 0, Name = 0, FirstThunk = 0):
        self.Characteristics = Characteristics
        self.OriginalFirstThunk = OriginalFirstThunk
        self.TimeDateStamp = TimeDateStamp
        self.ForwarderChain = ForwarderChain
        self.Name = Name
        self.FirstThunk = FirstThunk

    def isZeroed(self):
        return (self.Characteristics == 0 and
                self.OriginalFirstThunk == 0 and
                self.TimeDateStamp == 0 and
                self.ForwarderChain == 0 and
                self.Name == 0 and
                self.FirstThunk == 0)