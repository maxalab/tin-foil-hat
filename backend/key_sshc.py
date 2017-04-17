import paramiko
import re
MAX_IPTABLE_MARK = 0x7fff
DEFAULT_MTU = 1500
KERNEL_HZ = 100 #Default for tplink wrn

class SimpleSSH(object):
    def __init__(self, host, user, keyfile):
        self.keyfile = keyfile
        self.host = host
        self.user = user
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.load_system_host_keys()

    def connect(self):
        self.client.connect(self.host,
                            username=self.user,
                            key_filename=self.keyfile,
                            allow_agent=False)
        return self

    __enter__ = connect

    def __exit__(self, exc_type, exc_value, traceback):
        self.client.close()

    def execute_cmd(self, cmd, in_str=None):
        ch = self.client.get_transport().open_session()
        ch.exec_command(cmd)

        if in_str is not None:
            with ch.makefile('wb') as stdin:
                stdin.write(in_str)

        stdout = ch.makefile('r')
        stderr = ch.makefile_stderr('r')
        exitst = ch.recv_exit_status()

        return stdout.read(), stderr.read(), exitst

class TcError(Exception):
    pass

class TcManager(object):
    """For iperf traffic create a class under root and make two subclasses one for main traffic another for iperf. Parent class rate = sum of both subclasses

    Is mark in hex as a handle of filter? -- it's decimal, but all other
    handles, classids, parents are hex

    Is it necessary to create intermediate class for common (not iperf) cases?
    -- not, root classes don't share traffic with each other

    Does the second device need shaping? -- No
   """
    def __init__(self, host, username, keyfile, lan, wan, ip):
        self.ssh_client = SimpleSSH(host, username, keyfile)
        self.lan = {'name': lan,
                    'mtu': None}
        self.wan = {'name': wan,
                    'mtu': None}
        self.ip = ip
        self.mark = None
        self.parent = 1 # For HTB filter should be always set to root qdisc
        self.history = []

    def __enter__(self):
        self.ssh_client.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for op in self.history:
            print op
            try:
                self.execute(op)
            except TcError as e:
                if ("iptables: No chain/target/match by that name"
                    in e.message) or ("RTNETLINK answers: No such file or " \
                                      "directory" in e.message):
                    pass
                else:
                    raise e

        self.ssh_client.__exit__(exc_type, exc_value, traceback)

    def execute(self, cmd, in_str=None):
        cmd_out, cmd_err, cmd_st = self.ssh_client.execute_cmd(cmd, in_str)
        if cmd_st != 0:
            raise TcError(cmd_err)
        else:
            return cmd_out

    def _get_all_rules(self):
        cmd = "/usr/sbin/iptables -t mangle -L FORWARD --line-numbers"
        list_out = self.execute(cmd)
        lines = list_out.split("\n")
        rules = [l for l in lines if "MARK" in l]
        return rules

    def _get_tfl_rules(self):
        rules = [l for l in self._get_all_rules() if "tfh" in l]
        return rules

    def _get_mark_per_ip(self):
        marks = [int(r.split(" ")[-1], 16) for r in self._get_tfl_rules()
                 if self.ip in r]
        return marks

    def _get_complementary_iface(self, iface):
        if iface['name'] == self.lan['name']:
            return self.wan
        else:
            return self.lan

    def _get_mtu(self, iface):
        cmd = "/sbin/ifconfig {iface}".format(iface=iface['name'])
        ifconfig_out = self.execute(cmd)
        lines = ifconfig_out.split("\n")
        for l in lines:
            if re.search('MTU:([0-9]+)', l):
                return int(re.search('MTU:([0-9]+)', l).group(1))
        return DEFAULT_MTU

    def _calc_burst(self, iface, rate):
        """HOWTO estimate burst? -- rate/100(i386_hz)/8(in bytes) + mtu"""
        #burst = rate(in bits)/100(kernel_hz) + mtu
        return rate * 1000 / KERNEL_HZ + iface['mtu']
        #return int(rate * 1000 * 0.2 / 8) # 20% rate in bytes
        #return 12000

    def init_root(self, iface):
        cmd = "/usr/sbin/tc qdisc show dev {}".format(iface['name'])
        show_out = self.execute(cmd)
        lines = show_out.split("\n")
        if (lines[0] == "") or any(
                [("root" in l) and ("htb" not in l) for l in lines]):
            cmd = "/usr/sbin/tc qdisc add dev {} handle 1: root htb"\
                  .format(iface['name'])
            self.execute(cmd)

    def reset_root(self, iface):
        cmd = "/usr/sbin/tc qdisc del dev {} root".format(iface['name'])
        self.execute(cmd)

    def reset_iptable(self):
        rules = self._get_tfl_rules()
        rule_nums = [r.split(" ")[0] for r in rules]
        for n in sorted(rule_nums, reverse=1):
            cmd = "/usr/sbin/iptables -t mangle -D FORWARD {}".format(n)
            self.execute(cmd)

    def new_mark(self):
        """
        Mark should be created on the opposite iface to a shaped one.

        marks are "unsigned longs", so at least 2^32 of them should be
        available.
        Both major and minor are hexadecimal numbers
        and are limited to 16 bits
        => 16 bit numbers are available for marks. netem qdiscs are started
        from 0x8000 + hex(mark), as they allocate 50% of addresses
        (1 for netem, 1 for class).
        NOTE: if iperf is necessary, which number will it have? -- as the very
        simple desicion use only odd numbers for marks (16383 clients available)

        iptables may have other marks set that will impact tc routing. They
        should be filtered out.
        """
        rules = self._get_all_rules()
        if len(rules) == 0:
            return 1
        else:
            marks = [int(r.split(" ")[-1], 16) for r in rules]
            free_marks = set(range(1, max(marks), 2)) - set(marks)
            try:
                mark = min(free_marks)
            except ValueError:
                mark = max(marks) + 1 + max(marks) % 2
            if mark > MAX_IPTABLE_MARK:
                raise ValueError(
                    'Too large iptable mark value: {}'.format(mark))
            else:
                return mark

    def set_mark(self, iface):
        if iface['name'] == self.lan['name']:
            opt = "-s"
        else:
            opt = "-d"
        cmd = '/usr/sbin/iptables -t mangle -A FORWARD {opt} {ip} ' \
              '-i {iface} -j MARK --set-mark {mark} -m comment ' \
              '--comment "tfl_{ip}"'.format(
                  opt=opt, ip=self.ip, iface=iface['name'], mark=self.mark)
        self.history.append(cmd)

    def remove_mark(self, iface, mark=None):
        if iface['name'] == self.lan['name']:
            opt = "-s"
        else:
            opt = "-d"
        if mark is None:
            mark = self.mark
        cmd = '/usr/sbin/iptables -t mangle -D FORWARD {opt} {ip} ' \
              '-i {iface} -j MARK --set-mark {mark} -m comment ' \
              '--comment "tfl_{ip}"'.format(
                  opt=opt, ip=self.ip, iface=iface['name'], mark=mark)
        self.history.append(cmd)

    def create_class(self, iface, rate, parent=None):
        if parent is None:
            parent = self.parent
        #Use default burst, it doesn't correlate with filter burst
        cmd = "/usr/sbin/tc class add dev {iface} parent {parent}: " \
              "classid {parent}:{mark} htb rate {rate}kbit".format(
                  iface=iface['name'], parent=parent,
                  mark=format(self.mark, 'x'), rate=rate)
        self.history.append(cmd)

    def update_class(self, iface, rate, parent=None):
        if parent is None:
            parent = self.parent
        #Use default burst, it doesn't correlate with filter burst
        cmd = "/usr/sbin/tc class change dev {iface} parent {parent}: " \
              "classid {parent}:{mark} htb rate {rate}kbit".format(
                  iface=iface['name'], parent=parent,
                  mark=format(self.mark, 'x'), rate=rate)
        self.history.append(cmd)

    def remove_class(self, iface, mark=None, parent=None):
        if parent is None:
            parent = self.parent

        if mark is None:
            mark = self.mark

        cmd = "/usr/sbin/tc class del dev {iface} " \
              "classid {parent}:{mark}".format(
                  iface=iface['name'], parent=parent,
                  mark=format(mark, 'x'))

        self.history.append(cmd)

    def create_filter(self, iface, rate, police=None):
        # htb filters should be assigned to the htb root.
        cmd = "/usr/sbin/tc filter add dev {iface} parent {parent}: " \
              "handle {mark} prio 1 protocol ip fw " \
              "flowid {parent}:{mark}".format(
                  iface=iface['name'], parent=self.parent, mark=hex(self.mark))
        if police is not None:
            cmd += " police rate {rate}kbit burst {burst} drop".format(
                rate=rate, burst=self._calc_burst(iface, rate))
        self.history.append(cmd)

    def update_filter(self, iface, rate, police=None):
        # "tc filter change" leaves its target class blocked even after
        # removal.
        self.remove_filter(iface)
        self.create_filter(iface, rate, police)

    def remove_filter(self, iface, mark=None):
        if mark is None:
            mark = self.mark
        cmd = "/usr/sbin/tc filter del dev {iface} parent {parent}: " \
              "handle {mark} protocol ip prio 1 fw".format(
                  iface=iface['name'], parent=self.parent, mark=hex(mark))
        self.history.append(cmd)


    def create_leaf(self, iface, rate, net_buffer, delay, jitter, loss):
        """
        Burst/ceil/filter options to emulate correct limit in netem (do not
        estimate limit) -- there is no possibility to create buffer via htb =>
        rate/(MTU*8) = garanteed (minimal) number of packets to be send per
        second => rate/(MTU*8)/((BUFFER+DELAY)/1000) = netem limit in packets
        =>rate/(MTU*8)/((BUFFER+DELAY)/1000) + 1 - for non-zero rounding"""
        limit = int(rate * 1000/(8 * iface['mtu'])
                    * ((net_buffer + delay ) / 1000) + 1)
        #rate/(8 * self.mtu) * ((self.limit + self.delay ) / 1000) + 1
        handle = MAX_IPTABLE_MARK + 1 + int(self.mark)
        cmd = "/usr/sbin/tc qdisc add dev {iface} parent {parent}:{mark} " \
              "handle {handle}: netem limit {limit} delay {delay}ms " \
              "{jitter}ms loss {loss}%".format(
                  iface=iface['name'], parent=self.parent,
                  mark=format(self.mark, 'x'), handle=format(handle, 'x'),
                  limit=limit, delay=delay, jitter=jitter, loss=loss)
        self.history.append(cmd)

    def update_leaf(self, iface, rate, net_buffer, delay, jitter, loss):
        handle = MAX_IPTABLE_MARK + 1 + int(self.mark)
        limit = int(rate * 1000/(8 * iface['mtu'])
                    * ((net_buffer + delay ) / 1000) + 1)
        cmd = "/usr/sbin/tc qdisc change dev {iface} parent {parent}:{mark} " \
              "handle {handle}: netem limit {limit} delay {delay}ms " \
              "{jitter}ms loss {loss}%".format(
                  iface=iface['name'], parent=self.parent,
                  mark=format(self.mark, 'x'), handle=format(handle, 'x'),
                  limit=limit, delay=delay, jitter=jitter, loss=loss)
        self.history.append(cmd)


    def set_chain(self, iface_name, rate, net_buffer, delay, jitter, loss,
                  police=None):
        if self.mark is None:
            self.mark = self.new_mark()
        if self.lan['name'] == iface_name:
            iface = self.lan
        elif self.wan['name'] == iface_name:
            iface = self.wan
        else:
            raise ValueError('Unknown interface {}'.format(iface_name))
        iface['mtu'] = self._get_mtu(iface)
        self.init_root(iface)
        self.create_class(iface, rate)
        try:
            self.create_leaf(iface, rate, net_buffer, delay, jitter, loss)
            self.create_filter(iface, rate, police)
        except TcError as e:
            self.remove_class(iface)
            raise e
        self.set_mark(self._get_complementary_iface(iface))

    def update_chain(self, iface_name, rate, net_buffer, delay, jitter, loss,
                     police=None):
        if self.lan['name'] == iface_name:
            iface = self.lan
        elif self.wan['name'] == iface_name:
            iface = self.wan
        else:
            raise ValueError('Unknown interface {}'.format(iface_name))
        try:
            self.update_class(iface, rate)
            self.update_filter(iface, rate, police)
            self.update_leaf(iface, rate, net_buffer, delay, jitter, loss)
        except TcError as e:
            self.remove_class(iface)
            raise e

    def remove_chain(self, iface_name, mark=None):
        """In which order shaping chain should be removed? -- Filter first,
        then class. Child qdisc gets removed with its parent class.
        Signature for removal:
        -- filter: tc filter del dev br-lan parent 1: handle 100 prio 1
        protocol ip fw (note: decimal handle)
        -- class: tc class del dev br-lan classid 1:2
        -- qdisc: ... (it's not necessary)
        """

        if self.lan['name'] == iface_name:
            iface = self.lan
        elif self.wan['name'] == iface_name:
            iface = self.wan
        else:
            raise ValueError('Unknown interface {}'.format(iface_name))
        try:
            self.remove_mark(self._get_complementary_iface(iface), mark)
        except TcError as e:
            if "iptables: No chain/target/match by that name" in e.message:
                pass
            else:
                raise e
        try:
            self.remove_filter(iface, mark)
        except TcError as e:
            if "RTNETLINK answers: No such file or directory" in e.message:
                pass
            else:
                raise e
        try:
            self.remove_class(iface, mark)
        except TcError as e:
            if "RTNETLINK answers: No such file or directory" in e.message:
                pass
            else:
                raise e

    def reset_all_chains_for_ip(self):
        obsolete_marks = self._get_mark_per_ip()
        print obsolete_marks
        for m in set(obsolete_marks):
            self.remove_chain(self.wan['name'], m)
            self.remove_chain(self.lan['name'], m)

if __name__ == '__main__':
    CONFIG = {
        'host': "192.168.12.1",
        'username': 'root',
        'keyfile': "../../../tfl/tfl/tfl.key"
    }
    with TcManager(CONFIG['host'],
                   CONFIG['username'],
                   CONFIG['keyfile'], "br-lan", "eth1", "192.168.12.137") as tc_client:
        # TODO: verify default burst (as in emulator.sh)
        tc_client.set_chain('eth1', 200, 1000, 0, 0, 0)
        tc_client.set_chain('br-lan', 500, 1000, 0, 0, 0)
        # tc_client.update_chain('eth1', 100, 1000, 0, 0, 1)
        # tc_client.update_chain('br-lan', 300, 1000, 0, 0, 0)
        # tc_client.remove_chain('eth1')
        # tc_client.remove_chain('br-lan')
        tc_client.reset_all_chains_for_ip()
