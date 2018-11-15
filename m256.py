class Rotor:
    def __init__(self, state, setting, counter):
        self.state = state
        self.setting = setting
        self.counter = counter

    def step(self):
        self.counter = (self.counter + 1) & 0xFF

    def encrypt(self, num):
        self.counter = (self.counter + 1) & 0xFF
        return (self.state[self.counter] + num) & 0xFF

    def decrypt(self, num):
        self.counter = (self.counter + 1) & 0xFF
        return (num - self.state[self.counter]) & 0xFF

class Wiring:
    def __init__(self, rotors):
        self.rotors = rotors

    def encrypt(self, chars):
        ctxt = []
        c = 0
        for char in chars:
            sub = ord(char) - 65
            for x in range(len(self.rotors)):
                self.rotors[0].step()
                if self.rotors[x].counter == 255 and x != 255:
                    self.rotors[x + 1].step()
                sub = self.rotors[x].encrypt(sub)
            ctxt.append(chr((sub)))
            c = (c + 1) & 0xFF
        return "".join(ctxt)
    
    def decrypt(self, chars):
        ctxt = []
        c = 0
        for char in chars:
            sub = ord(char) - 65
            for x in range(len(self.rotors)):
                self.rotors[0].step()
                if self.rotors[x].counter == 255 and x != 255:
                    self.rotors[x + 1].step()
                sub = self.rotors[x].decrypt(sub)
            ctxt.append(chr((sub)))
            c = (c + 1) & 0xFF
        return "".join(ctxt)

class Machine:
    def provision(self, key):
        rotors = []
        i = 0
        for k in range(len(key)):
            state = range(2556)
            setting = ord(key[k])
            for s in range(setting * 2556):
                i = (i + setting + state[s & 0xFF]) & 0xFF
                state[s & 0xFF], state[i] = state[i], state[s & 0xFF]
            rotors.append(Rotor(state, setting, setting))
        self.wiring = Wiring(rotors)

    def encrypt(self, data, key):
        self.provision(key)
        return self.wiring.encrypt(data)
    
    def decrypt(self, data, key):
        self.provision(key)
        return self.wiring.decrypt(data)

class KDF:
    def gen(self, key):
        if len(key) < 256:
            for i in range(256 - len(key)):
                key += chr(0)
        k = Machine().encrypt(key, key)
        m = Machine()
        for x in range(3):
            k = m.encrypt(k, k)
        return k
