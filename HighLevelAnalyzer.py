from typing import Iterable, Optional, Union
from saleae.analyzers import (
    HighLevelAnalyzer,
    AnalyzerFrame,
)

regs_rd = {
    0x00: "RHR (Receive Holding Register)",
    0x01: "IER (Interrupt Enable Register)",
    0x02: "IIR (Interrupt Identification Register)",
    0x03: "LCR (Line Control Register)",
    0x04: "MCR (Modem Control Register)",
    0x05: "LSR (Line Status Register)",
    0x06: "MSR (Modem Status Register)",
    0x07: "SPR (Scratchpad Register)",
    0x08: "TXLVL (Transmit FIFO Level Register)",
    0x09: "RXLVL (Receive FIFO Level Register)",
    0x0A: "IODir (I/O pin Direction Register)",
    0x0B: "IOState (I/O pin States Register)",
    0x0C: "IOIntEna (I/O Interrupt Enable Register)",
    0x0E: "IOControl (I/O pins Control Register)",
    0x0F: "EFCR (Extra Features Register)",
    0x16: "TCR (Transmission Control Register)",
    0x17: "TLR (Transmission Level Register)",
    0x20: "DLL (divisor latch LSB)",
    0x21: "DLH (divisor latch MSB)",
    0x42: "EFR (Enhanced Feature Register)",
    0x44: "XON1 (Xon1 word)",
    0x45: "XON2 (Xon2 word)",
    0x46: "XOFF1 (Xoff1 word)",
    0x47: "XOFF2 (Xoff2 word)",
}

regs_wr = {
    0x00: "THR (Transmit Holding Register)",
    0x01: "IER (Interrupt Enable Register)",
    0x02: "FCR (FIFO Control Register)",
    0x03: "LCR (Line Control Register)",
    0x04: "MCR (Modem Control Register)",
    0x07: "SPR (Scratchpad Register)",
    0x0A: "IODir (I/O pin Direction Register)",
    0x0B: "IOState (I/O pin States Register)",
    0x0C: "IOIntEna (I/O Interrupt Enable Register)",
    0x0E: "IOControl (I/O pins Control Register)",
    0x0F: "EFCR (Extra Features Register)",
    0x16: "TCR (Transmission Control Register)",
    0x17: "TLR (Transmission Level Register)",
    0x20: "DLL (divisor latch LSB)",
    0x21: "DLH (divisor latch MSB)",
    0x42: "EFR (Enhanced Feature Register)",
    0x44: "XON1 (Xon1 word)",
    0x45: "XON2 (Xon2 word)",
    0x46: "XOFF1 (Xoff1 word)",
    0x47: "XOFF2 (Xoff2 word)",
}


def get_reg_rd_name(address: int) -> str:
    """Get the register name when Read by address."""
    try:
        return regs_rd[address]
    except KeyError:
        return f"0x{address:02X}"

def get_reg_wr_name(address: int) -> str:
    """Get the register name when Write by address."""
    try:
        return regs_wr[address]
    except KeyError:
        return f"0x{address:02X}"

def get_enabled(byte :int, str0: str, str1: str, str2: str, str3: str, str4: str, str5: str, str6: str, str7: str) -> str:
    enabled = ""
    if ((byte >> 7) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str7
    if ((byte >> 6) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str6
    if ((byte >> 5) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str5
    if ((byte >> 4) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str4
    if ((byte >> 3) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str3
    if ((byte >> 2) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str2
    if ((byte >> 1) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str1
    if ((byte >> 0) & 0b1 == 0b1):
        if enabled != "":
            enabled += " | "
        enabled += str0
    if enabled == "":
        enabled += "None"
    return enabled

class Hla(HighLevelAnalyzer):
    """sc16is7x0 High Level Analyzer."""

    result_types = {
        "register": {"format": "{{data.rw}} {{data.reg}} : {{data.desc}}"},
    }

    def __init__(self):
        """Initialize HLA."""

        # Previous frame type
        # https://support.saleae.com/extensions/analyzer-frame-types/spi-analyzer
        self._previous_type: str = ""
        # current address
        self._address: Optional[int] = None
        # current access type
        self._rw: str = ""
        # current byte position
        self._byte_pos: int = 0
        # current tcr_tlr number
        self._tcr_tlr: int = 0x00
        # current sr number
        self._sr: int = 0x00
        # current efr number
        self._efr: int = 0x00

        self._start_of_address_frame = None

    def decode(
        self, frame: AnalyzerFrame
    ) -> Optional[Union[Iterable[AnalyzerFrame], AnalyzerFrame]]:
        """Decode frames."""
        is_first_byte: bool = self._previous_type == "enable"
        self._previous_type: str = frame.type

        if is_first_byte:
            self._byte_pos = 0
        else:
            self._byte_pos += 1

        if frame.type != "result":
            return None

        mosi: bytes = frame.data["mosi"]
        miso: bytes = frame.data["miso"]

        if self._byte_pos == 0:
            try:
                self._address = (mosi[0] >> 3 & 0b1111)
                self._rw = "Read" if ((mosi[0] >> 7) & 0b1 == 0b1) else "Write"
            except IndexError:
                return None
            self._start_of_address_frame = frame.start_time
            if (self._address >= 0x00) and (self._address <= 0x01):
                self._address += self._sr
            if (self._address >= 0x02) and (self._address <= 0x07):
                self._address += self._efr
            if ((self._address >= 0x06) and (self._address <= 0x07)) and self._efr == 0:
                self._address += self._tcr_tlr
            return None
        if self._byte_pos > 0:
            if self._rw.lower() == "write":
                name = get_reg_wr_name(self._address)
                try:
                    byte = mosi[0]
                except IndexError:
                    return None
            else:
                name = get_reg_rd_name(self._address)
                try:
                    byte = miso[0]
                except IndexError:
                    return None

            desc = ""
            if self._address == 0x01: # IER
                desc = get_enabled(byte, "Receive Holding", "Transmit Holding", "Receive Line Status", "Modem Status", "Sleep", "Xoff", "RTS#", "CTS#")
            elif self._address == 0x02: # FCR
                desc = get_enabled(byte & 0b111, "FIFO enable", "Reset RX FIFO", "Rest TX FIFO", "", "", "", "", "")
                if (byte >> 4) & 0b11 == 0b00:
                    desc += " | TX trigger 8 spaces"
                elif (byte >> 4) & 0b11 == 0b01:
                    desc += " | TX trigger 16 spaces"
                elif (byte >> 4) & 0b11 == 0b10:
                    desc += " | TX trigger 32 spaces"
                else:
                    desc += " | TX trigger 56 spaces"
                if (byte >> 6) & 0b11 == 0b00:
                    desc += " | RX trigger 8 spaces"
                elif (byte >> 6) & 0b11 == 0b01:
                    desc += " | RX trigger 16 spaces"
                elif (byte >> 6) & 0b11 == 0b10:
                    desc += " | RX trigger 56 spaces"
                else:
                    desc += " | RX trigger 60 spaces"
            elif self._address == 0x03 or self._address == 0x43: # LCR
                # word length
                if (byte >> 0) & 0b11 == 0b00:
                    desc += "5"
                elif (byte >> 0) & 0b11 == 0b01:
                    desc += "6"
                elif (byte >> 0) & 0b11 == 0b10:
                    desc += "7"
                else:
                    desc += "8"
                # parity
                if (byte >> 3) & 0b1 == 0b0:
                    desc += "N"
                else:
                    if (byte >> 5) & 0b1 == 0b0:
                        if (byte >> 4) & 0b1 == 0b0:
                            desc += "O"
                        else:
                            desc += "E"
                    else:
                        if (byte >> 4) & 0b1 == 0b0:
                            desc += "S"
                        else:
                            desc += "C"
                # stop bit length
                if (byte >> 2) & 0b1 == 0b0:
                    desc += "1"
                else:
                    if (byte >> 0) & 0b11 == 0b00:
                        # 5bits
                        desc += "1.5"
                    else:
                        desc += "2"
                # Break control
                if (byte >> 6) & 0b1 == 0b1:
                    desc += " | Break control"
                # EFR/SR enable
                if (byte == 0xBF):
                    self._efr = 0x40
                    self._sr = 0x00
                    desc += " | Enable EFR"
                else:
                    self._efr = 0x00
                    if (byte >> 7) & 0b1 == 0b1:
                        self._sr = 0x20
                        desc += " | Enable SR"
                    else:
                        self._sr = 0x00
            elif self._address == 0x04: # LSR
                if ((byte >> 2) & 0b1 == 0b1):
                    self._tcr_tlr = 0x10
                else:
                    self._tcr_tlr = 0x00
                desc = get_enabled(byte, "DTR# active", "RTS# active", "TCR/TLR enable", "", "loopback", "Xon any", "IrDA", "divide-by-4 clock input")
            elif self._address == 0x05: # LSR
                desc = get_enabled(byte, "data in", "overrun error", "parity error", "framing error", "break interrupt", "THR empty", "THR and TSR empty", "FIFO data error")
            elif self._address == 0x0E: # IOControl
                desc = get_enabled(byte, "input values are latched", "GPIO[7:4] behave as RI#, CD#, DTR#, DSR#", "", "Software Reset", "", "", "", "")
            elif self._address == 0x0F: # EFCR
                desc = get_enabled(byte, "9-Bit Mode", "RX Disable", "TX Disable", "", "RTS Control", "RTS Invert", "", "IRDA Mode")
            elif self._address == 0x16: # TCR
                halt = byte & 0b1111
                resume = (byte >> 4) & 0b1111
                desc = f"RX FIFO halt at {halt*4}, resume at {resume*4}"
            elif self._address == 0x17: # TLR
                tx_trig = byte & 0b1111
                rx_trig = (byte >> 4) & 0b1111
                desc = f"TX FIFO trigger level {tx_trig}, RX FIFO trigger level  {rx_trig}"
                # desc = get_enabled(byte, "", "", "", "", "", "", "", "")
            elif self._address == 0x42: # EFR
                self._efr = 0x00
                # TX Flow Control
                if (byte >> 2) & 0b1 == 0b0:
                    if (byte >> 3) & 0b1 == 0b0:
                        desc = "no TX flow control | "
                    else:
                        desc = "TX transmit Xon1, Xoff1 | "
                else:
                    if (byte >> 3) & 0b1 == 0b0:
                        desc = "TX transmit Xon2, Xoff2 | "
                    else:
                        desc = "TX transmit Xon1 and Xon2, Xoff1 and Xoff2 | "
                # RX Flow Control
                if (byte >> 0) & 0b1 == 0b0:
                    if (byte >> 1) & 0b1 == 0b0:
                        desc += "no RX flow control"
                    else:
                        desc += "RX compare Xon1, Xoff1"
                else:
                    if (byte >> 1) & 0b1 == 0b1:
                        if (byte >> 2) & 0b1 == (byte >> 3) & 0b1:
                            desc += "RX compare Xon1 and Xon2, Xoff1 and Xoff2"
                        else:
                            desc += "RX compare Xon1 or Xon2, Xoff1 or Xoff2"
                desc += " | " + get_enabled(byte & 0b11110000, "", "", "", "", "Enhanced functions", "Special Char Detect", "RTS#", "CTS#")
            else:
                desc = f"0x{byte:02X}"
            return AnalyzerFrame(
                "register",
                start_time = self._start_of_address_frame,
                end_time = frame.end_time,
                data = {
                    "reg": name,
                    "rw": self._rw,
                    "desc": desc,
                },
            )
