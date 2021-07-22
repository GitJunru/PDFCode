#! /usr/bin/env python
# coding=utf-8

class Stream:
    def __init__(self):
        self.lines = ""     # 保存整个文件的一个字符串lines
        self.analysis = {}
        self.pos = 0

    def ReadFile(self, filename):
        input1 = open(filename, "rb")
        self.lines = input1.read()
        input1.close()
        self.pos = 0

    def SetStream(self, stream):
        self.lines = stream
        self.pos = 0

    def isEOF(self):
        return self.pos >= len(self.lines)

    def get_pos(self):
        return self.pos

    def set_pos(self, pos):
        self.pos = pos

    def add_pos(self, add):
        self.pos += add

    # get without unescape
    # 获取一个字符
    def get(self):
        self.pos_ = self.get_pos()
        if self.isEOF():
            self.pos += 1
            return "EOF"
        else:
            ret = self.lines[self.pos]
            self.pos += 1
            return ret

    # get with unescape
    # 读一个字符，用解码的方式：如果读到#xx，返回xx
    def get_u(self):
        pos = self.get_pos()
        tok = self.get()
        if tok == "EOF":
            return "EOF"
        elif tok == '#':
            # '#xx' to charCode
            tok2 = self.get() + self.get()
            if tok2 == '20' or tok2 == '2F' or tok2 == '2f' or tok2 == '28' or tok2 == '29' or tok2 == '25' or tok2 == '5b' or tok2 == '5B' or tok2 == '5d' or tok2 == '5D':
                ret = tok
                self.add_pos(-2)
            else:
                try:
                    ret = chr(int(tok2, base=16))
                except ValueError:
                    ret = tok
                    self.add_pos(-2)
        else:
            ret = tok

        self.pos_ = pos
        return ret

    def bak_pos(self):
        self.set_pos(self.pos_)

    def skip_blank(self):
        pos = self.get_pos()
        tok = self.get_u()
        while tok in ('\x00', '\r', '\n', '\t', '\f', ' '):
            pos = self.get_pos()
            tok = self.get_u()
        self.set_pos(pos)

    def read_line(self):
        ret = ""
        tok = self.get()
        while tok != "EOF":
            if tok == '\r':
                ret += tok
                tok2 = self.get()
                if tok2 == '\n':
                    ret += tok2
                else:
                    self.add_pos(-1)
                break
            elif tok == '\n':
                ret += tok
                tok2 = self.get()
                if tok2 == '\r':
                    ret += tok2
                else:
                    self.add_pos(-1)
                break
            else:
                ret += tok
            tok = self.get()
        return ret

    # 读一整行数据，一直读到\r或者\n结束
    def read_line_u(self):
        ret = ""
        tok = self.get_u()
        while tok != "EOF":
            if tok == '\r':
                ret += tok
                pos = self.get_pos()
                tok2 = self.get_u()
                if tok2 == '\n':
                    ret += tok2
                else:
                    self.set_pos(pos)
                break
            elif tok == '\n':
                ret += tok
                pos = self.get_pos()
                tok2 = self.get_u()
                if tok2 == '\r':
                    ret += tok2
                else:
                    self.set_pos(pos)
                break
            else:
                ret += tok
            tok = self.get_u()
        return ret

    # 读一个边界字符或者读一段有效数据
    def read_phrase_u(self):
        ret = ""
        # self.skip_blank()
        tok = self.get_u()
        if tok in ('(', ')', '<', '>', '[', ']', '/', '%'):
            ret = tok
        else:
            pos = self.get_pos()
            while tok not in ('\x00', '\r', '\n', '\t', '\f', ' ', 'EOF', '(',
                              ')', '<', '>', '[', ']', '/', '%'):
                ret += tok
                pos = self.get_pos()
                tok = self.get_u()
            self.set_pos(pos)
        self.skip_blank()
        return ret
