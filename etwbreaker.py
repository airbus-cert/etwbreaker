"""
ETWBreaker is an IDA plugin that find all references about ETW into a module

Currently ETWBreaker can work with Manifest-based ETW and Tracelogging.

For Manifest-based ETW, ETWBreaker will parse module ressources to find and parse the manifest
and show all possible events handled by the current module.

It tries to parse also all tracelogging events, which are more hidden than Manifest-based ones.

In the end ETWBreaker can generate a conditional breakpoint to dynamically analyze events.
"""

import idaapi
import idautils
import ida_dbg
import ida_name
import idc
import sys
import struct
import textwrap
from io import BytesIO
from PyQt5 import QtCore, QtWidgets, QtGui
from typing import List, Tuple

__author__ = "Airbus CERT"


class ETWBreakerException(Exception):
    """
    Base exception for all exception of ETW breaker
    """
    def __init__(self, message):
        super().__init__(message)


class ETWBreakerWevtTemplateNotFound(ETWBreakerException):
    """
    The WEVT_TEMPLATE ressource was not found
    """
    def __init__(self):
        super().__init__("WEVT_TEMPLATE resource not found.")


class ETWBreakerTLNotFound(ETWBreakerException):
    """
    The tracelogging magic was not found
    """
    def __init__(self):
        super().__init__("Trace logging not found")


class ETWBreakerUnexpectedToken(ETWBreakerException):
    """
    During parsing an unexpected token was found.
    Please open an issue on Github.
    """
    def __init__(self, expected, found):
        super().__init__("Unexpected token. Expected %s, found %s"%(expected, found))


class Stream(BytesIO):
    """
    A wrapper that is nicer to understand
    """
    def read_u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def read_u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def read_u8(self) -> int:
        return struct.unpack("<B", self.read(1))[0]

    def read_u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]


class Guid:
    """
    A global unique identifier
    """
    def __init__(self, raw):
        self.raw = raw

    def __str__(self):
        Data1 = struct.unpack("<I", self.raw[0:4])[0]
        Data2 = struct.unpack("<H", self.raw[4:6])[0]
        Data3 = struct.unpack("<H", self.raw[6:8])[0]
        Data4 = self.raw[8:16]
        return "%08x-%04x-%04x-%s-%s" % (Data1, Data2, Data3, "".join("%02x" % x for x in Data4[0:2]), "".join("%02x" % x for x in Data4[2:]))



class ETWBreaker(idaapi.ida_idaapi.plugin_t):
    """
    This is the main plugin class
    """
    comment = ""
    help = ""
    flags = idaapi.PLUGIN_MOD
    wanted_name = 'ETWBreaker'
    wanted_hotkey = 'Ctrl-Shift-L'
    hxehook = None

    def init(self):
        """
        Init plugin function
        """
        if idc.get_inf_attr(idc.INF_FILETYPE) != idc.FT_PE:
            # skip if it's not a PE
            return idaapi.PLUGIN_SKIP
        ETWBreaker.log("'%s' loaded. %s activates/deactivates synchronization." % (ETWBreaker.wanted_name, ETWBreaker.wanted_hotkey))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Launch when you press Ctrl-Shift-L
        """
        ETWBreaker.log("%s is enabled now." % ETWBreaker.wanted_name)
        providers = []

        # Manifest based provider
        try:
            providers += parse_manifest(find_wevt_template(*find_segment(".rsrc")[0]))
        except IndexError:
            ETWBreaker.log("Please consider reloading the file and check the 'Load resources' checkbox")
        except ETWBreakerException as e:
            ETWBreaker.log(str(e))

        # Tracelogging
        for segment in find_segment(".rdata"):
            try:
                providers += parse_tracelogging(find_tracelogging_meta(*segment))
            except ETWBreakerException as e:
                ETWBreaker.log(str(e))

        ETWResultsForm(providers).show()


    def term(self):
        ETWBreaker.log("%s unloaded." % (ETWBreaker.wanted_name))

    def log(message):
        idaapi.msg("[%s] %s\n" % (ETWBreaker.wanted_name, message))


class Event:
    """
    An ETW event
    """
    def __init__(self, event_id: int, version: int, channel: int, level: int, opcode: int, task: int, keyword: int):
        self.event_id = event_id
        self.version = version
        self.channel = channel
        self.level = level
        self.opcode = opcode
        self.task = task
        self.keyword = keyword

    def find_symbol(self) -> str:
        """
        Try to find a symbol associated to the event

        This is based on the event header signature
        Most of then are into .rdata segment and some of them have a name
        """
        pattern = struct.pack("<HBBBBHQ", self.event_id, self.version, self.channel, self.level, self.opcode, self.task, self.keyword)
        for start, end in find_segment(".rdata"):
            offset = idc.get_bytes(start, end - start).find(pattern)
            if offset == -1:
                continue

            name = ida_name.get_name(start+offset)
            if name is None:
                continue

            return name
        return None


class Channel:
    """
    Channel is a pure ETW concept
    """
    def __init__(self, identifier: int, name: str):
        """
        :ivar identifier: unique identifier of the channel
        :ivar name: name of the channel, generally include the provider name
        """
        self.identifier = identifier
        self.name = name

    def __str__(self):
        return self.name


class Provider:
    """
    An ETW Provider is defined by a unique GUID
    and a list of event
    """
    def __init__(self, guid: Guid, events: List[Event], channels: List[Channel]):
        """
        :ivar guid: An unique global identifier
        :ivar events: A list of event that could be emitted  by the provider
        :ivar channels: A list of all channel identifier available
        """
        self.guid = guid
        self.events = events
        self.channels = channels

    def find_channel(self, identifier: int) -> Channel:
        """
        Try to find a channel from its identifier
        """
        return next((channel for channel in self.channels if channel.identifier == identifier), None)


class ManifestProvider(Provider):
    """
    Convenient class use to identify Manifest based providers
    """


class TraceLoggingProvider(Provider):
    """
     Convenient class use to identify TraceLogging providers
    """


def find_segment(name: str) -> List[Tuple[int, int]]:
    """
    Try to find the segment from name

    :ivar name: name of segment
    :ret: Start ant end address
    """
    result = []
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == name:
            result.append((idc.get_segm_start(seg), idc.get_segm_end(seg)))
    return result


def find_wevt_template(start, end) -> Stream:
    """
    This function try to retrieve the WEVT_TEMPLETE resource
    This resource start with the magic CRIM

    :ivar start: start address
    :ivar end: end address
    :ret: Stream use to parse Manifest based provider or raise an exception
    :raise: ETWBreakerWevtTemplateNotFound
    """
    resource = idc.get_bytes(start, end - start)
    result = resource.find(b"CRIM")
    if result == -1:
        raise ETWBreakerWevtTemplateNotFound()

    return Stream(resource[result:])


def find_tracelogging_meta(start, end) -> Stream:
    """
    Try to find ETW0 magic

    :ivar start: start address
    :ivar end: end address
    :ret: Stream use to parse tracelogging or None if not found
    """
    data = idc.get_bytes(start, end - start)
    result = data.find(b"ETW0")
    if result == -1:
        raise ETWBreakerTLNotFound()

    return Stream(data[result:])


def parse_tracelogging_event(stream: Stream) -> Event:
    """
    A tracelogging event is identified by its channel number_of_channel
    that are always 11. Actually we can't handle tracelogging event
    because the lonk between event and provider is made during code execution

    :ivar stream: current stream use to parse the event
    :ret: An event object for tracelogging
    """
    channel = stream.read_u8()
    if channel != 11:
        raise ETWBreakerUnexpectedToken(11, channel)
    level = stream.read_u8()
    opcode = stream.read_u8()
    keyword = stream.read_u64()
    size = stream.read_u16()
    stream.read(size - 2)
    return Event(0, 0, channel, level, opcode, 0, keyword)


def parse_tracelogging_provider(stream: Stream) -> Provider:
    """
    Create a default provider for tracelogging
    It will add a default event for this provider
    Because in traclogging all event have the event id set to 0

    :ivar stream: current stream use to parse the provider
    :ret: A provider object for tracelogging
    """
    guid = Guid(stream.read(16))
    size = stream.read_u16()
    payload = stream.read(size - 2)
    name = payload[:payload.find(b"\x00")].decode("ascii")

    return TraceLoggingProvider(guid, [Event(0, 0, 11, 0, 0, 0, 0)], [Channel(11, name)])


def parse_tracelogging(stream: Stream) -> List[Provider]:
    """
    Try to parse all tracelogging event and provider
    from an .rdata segmant

    Actually only provider are intersting. It's because the link
    between event and provider are made into the code dynamically.

    :ivar stream: current stream use to parse the event
    :ret: the list of all provider which are found
    """
    magic = stream.read(4)
    if magic != b"ETW0":
        raise ETWBreakerUnexpectedToken(b"ETW0", magic)

    stream.read(12)
    providers = []
    while True:
        type = stream.read_u8()
        if type == 6:
            parse_tracelogging_event(stream)
        elif type == 4:
            providers.append(parse_tracelogging_provider(stream))
        elif type == 0:
            # padding
            continue
        else:
            print("Unknown Trace logging type %s, expect to be the end of trace logging block"%type)
            break
    return providers


def parse_event_elements(stream: Stream) -> List[Event]:
    """
    Parse an event element
    An event is defined by :
    * unique identifier
    * a channel
    * a set of keywords
    * a level

    :ivar stream: Input stream once read the EVNT magic and the size of the payload
    :ret: List of all event parsed
    """
    number_of_event = stream.read_u32()
    stream.read(4) # padding

    events = []
    for i in range(0, number_of_event):
        event_id = stream.read_u16()
        version = stream.read_u8()
        channel = stream.read_u8()
        level = stream.read_u8()
        opcode = stream.read_u8()
        task = stream.read_u16()
        keywords = stream.read_u64()
        message_identifier = stream.read_u32()
        template_offset = stream.read_u32()
        opcode_offset = stream.read_u32()
        level_offset = stream.read_u32()
        task_offset = stream.read_u32()
        stream.read(12)
        events.append(Event(event_id, version, channel, level, opcode, task, keywords))
    return events


def parse_channel_element(stream: Stream) -> List[Channel] :
    number_of_channel = stream.read_u32()
    result = []
    for i in range(0, number_of_channel):
        unknown = stream.read_u32()
        offset = stream.read_u32()
        identifier = stream.read_u32()
        message_identifier = stream.read_u32()

        sub_stream = Stream(stream.getvalue())
        sub_stream.read(offset)
        size = sub_stream.read_u32()
        name = sub_stream.read(size-4).decode("utf-16le")
        result.append(Channel(identifier, name))
    return result


def parse_event_provider(guid: Guid, stream: Stream) -> Provider:
    """
    Parse an event provider
    An event provider is composed by a plenty of sort of element:
    * EVNT for event

    https://github.com/libyal/libfwevt/blob/master/libfwevt/fwevt_template.h

    :ivar guid: GUID of the provider
    :ivar stream: stream of the entire resource with offset set to the start of the provider
    """
    magic = stream.read(4)
    if magic != b"WEVT":
        raise ETWBreakerUnexpectedToken(b"WEVT", magic)

    size = stream.read_u32()
    message_table_id = stream.read_u32()

    number_of_element = stream.read_u32()
    number_of_unknown = stream.read_u32()

    element_descriptor = [(stream.read_u32(), stream.read_u32()) for i in range(0, number_of_element)]
    unknown = [stream.read_u32() for i in range(0, number_of_unknown)]

    events = []
    channels = []
    for offset, _ in element_descriptor:
        stream.seek(offset)
        magic = stream.read(4)
        size = stream.read_u32()

        # Event declaration
        if magic == b"EVNT":
            events = parse_event_elements(stream)
        elif magic == b"CHAN":
            channels = parse_channel_element(stream)

    return ManifestProvider(guid, events, channels)


def parse_manifest(stream: Stream) -> List[Provider]:
    """
    An ETW Manifest is a binary serialized
    It start with CRIM magic

    Then list all providers
    For each providers we can parse GUID and Provider description

    """
    magic = stream.read(4)
    if magic != b"CRIM":
        raise ETWBreakerUnexpectedToken(b"CRIM", magic)

    size = stream.read_u32()

    major_version = stream.read_u16()
    minor_version = stream.read_u16()

    number_of_provider_descriptor = stream.read_u32()

    # Read provider meta informations
    providers_descriptor = [(Guid(stream.read(16)), stream.read_u32()) for i in range(0, number_of_provider_descriptor)]

    # Parse providers
    providers = []
    for guid, offset in providers_descriptor:
        stream.seek(offset)
        providers.append(parse_event_provider(guid, stream))

    return providers


def add_breakpoint(guid: Guid, event: Event):
    """
    Add a software break point on ntdll!EtwEventWrite
    And set a condition on event id and event provider
    """
    bpt = idaapi.bpt_t()
    bpt.set_sym_bpt("ntdll_EtwEventWrite", 0)
    bpt.condition = textwrap.dedent("""
    import idaapi
    import idc

    rdx = idaapi.regval_t()
    idaapi.get_reg_val('RDX',rdx)
    event_id = int.from_bytes(idc.get_bytes(rdx.ival, 2), "little")

    rcx = idaapi.regval_t()
    idaapi.get_reg_val('RCX',rcx)
    provider_guid = idc.get_bytes((rcx.ival & 0xFFFFFFFFFFFF) + 0x20, 16)

    if event_id == %s and provider_guid == %s:
        print(f"[ETWBreaker] break on Provider {{%s}} EventId ({event_id})")
        return True
    else:
        return False
    """%(event.event_id, guid.raw, guid))
    bpt.elang = "Python"
    idaapi.add_bpt(bpt)


def delete_breakpoint(symbol: str):
    """
    Delete the breakpoint set on ntdll_EtwEventWrite
    """
    location = idaapi.bpt_location_t()
    location.set_sym_bpt(symbol)

    if idaapi.find_bpt(location, None):
        idaapi.del_bpt(location)


class ETWResultsModel(QtCore.QAbstractTableModel):
    """
    This class is QT class that help to view data from COM parsing
    """
    COL_ID = 0x00
    COL_TYPE = 0x01
    COL_GUID = 0x02
    COL_CHANNEL = 0x03
    COL_SYMBOL = 0x04


    def __init__(self, providers: List[Provider], parent=None):
        super().__init__(parent)

        self._column_headers = {
            ETWResultsModel.COL_ID : 'Event ID',
            ETWResultsModel.COL_TYPE : 'Type',
            ETWResultsModel.COL_GUID : 'GUID',
            ETWResultsModel.COL_CHANNEL : 'Channel',
            ETWResultsModel.COL_SYMBOL : 'Symbol'
        }

        self._results = []
        for provider in providers:
            self._results += [(provider, event) for event in provider.events]

        self._row_count = len(self._results)

    def flags(self, index):
        return QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

    def rowCount(self, index=QtCore.QModelIndex()):
        return self._row_count

    def columnCount(self, index=QtCore.QModelIndex()):
        return len(self._column_headers)

    def headerData(self, column, orientation, role=QtCore.Qt.DisplayRole):
        """
        Define the properties of the the table rows & columns.
        """
        if orientation == QtCore.Qt.Horizontal:

            # the title of the header columns has been requested
            if role == QtCore.Qt.DisplayRole:
                try:
                    return self._column_headers[column]
                except KeyError as e:
                    pass

            # the text alignment of the header has beeen requested
            elif role == QtCore.Qt.TextAlignmentRole:

                # center align all columns
                return QtCore.Qt.AlignHCenter

        # unhandled header request
        return None

    def data(self, index, role=QtCore.Qt.DisplayRole):
        """
        Define how Qt should access the underlying model data.
        """
        # data display request
        if role == QtCore.Qt.DisplayRole:

            # grab for speed
            row = index.row()
            column = index.column()

            if column == ETWResultsModel.COL_GUID:
                return "{%s}"%(self._results[row][0].guid)
            elif column == ETWResultsModel.COL_ID:
                return self._results[row][1].event_id
            elif column == ETWResultsModel.COL_CHANNEL:
                event = self._results[row][1]
                return str(self._results[row][0].find_channel(event.channel) or "Unknown channel")
            elif column == ETWResultsModel.COL_TYPE:
                return self._results[row][0].__class__.__name__
            elif column == ETWResultsModel.COL_SYMBOL:
                return self._results[row][1].find_symbol() or "No symbol"

        # font color request
        elif role == QtCore.Qt.ForegroundRole:
            return QtGui.QColor(QtCore.Qt.black)

        # unhandeled request, nothing to do
        return None


class ETWResultsForm(idaapi.PluginForm):
    """
    The Qt form use to display ETW table
    """
    def __init__(self, providers: List[Provider]):

        super().__init__()
        self.providers = providers

    def OnCreate(self, form):
        """
        Initialize the custom PyQt5 content on form creation.
        """
        # Get parent widget
        self._widget  = self.FormToPyQtWidget(form)
        self._init_ui()

    def show(self):
        """
        Make the created form visible as a tabbed view.
        """
        flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_PERSIST
        return idaapi.PluginForm.Show(self, "ETW", flags)


    def _init_ui(self):
        """
        Init ui of ETW table
        """
        self._model = ETWResultsModel(self.providers, self._widget)
        self._table = QtWidgets.QTableView()

        # set these properties so the user can arbitrarily shrink the table
        self._table.setMinimumHeight(0)
        self._table.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Ignored
        )

        self._table.setModel(self._model)

        # set a windbg breakpoint on double click
        self._table.doubleClicked.connect(self._ui_entry_double_click)

        # table selection should be by row, not by cell
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # more code-friendly, readable aliases
        vh = self._table.verticalHeader()
        hh = self._table.horizontalHeader()
        vh.setSectionResizeMode(QtWidgets.QHeaderView.Fixed)

        # hide the vertical header themselves as we don't need them
        vh.hide()

        # Allow multiline cells
        self._table.setWordWrap(True)
        self._table.setTextElideMode(QtCore.Qt.ElideMiddle);
        self._table.resizeColumnsToContents()
        self._table.resizeRowsToContents()

        layout = QtWidgets.QGridLayout()
        layout.addWidget(self._table)
        self._widget.setLayout(layout)

    def _ui_entry_double_click(self, index):
        """
        When user click on an event
        we send to windbg a special crafted debug command

        That will set a conditional breakpoint on ntdll!EtwEventWrite function
        with condition on function argument that match the eventid and the provider GUID
        """
        event = self._model._results[index.row()][1]
        guid = self._model._results[index.row()][0].guid
        delete_breakpoint("ntdll_EtwEventWrite")
        add_breakpoint(guid, event)


def PLUGIN_ENTRY():
    return ETWBreaker()
