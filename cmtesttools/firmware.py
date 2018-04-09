from elftools.elf.elffile import ELFFile

class Firmware(object):

    def __init__(self, elf_path):
        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            text_sec = elf.get_section_by_name(".text")
            if text_sec is None:
                raise ValueError("No text section")
            
            self.segments = []
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD":
                    self.segments.append([seg["p_paddr"], seg.data()]);

    def get_segments(self):
        return self.segments
