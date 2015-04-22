#!/usr/bin/env python2
import pefile
import struct
import re

guid_regex = re.compile("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")


def format_guid_from_hex(hex_string):
    first = hex_string[6:8] + hex_string[4:6] + hex_string[2:4] + hex_string[:2]
    second = hex_string[10:12] + hex_string[8:10]
    return "{0}-{1}-{2}-{3}-{4}".format(first, second, hex_string[12:16], hex_string[16:20],
                                        hex_string[20:])


def read_blob(blob):
    if len(blob) == 0:
        return ""
    first_byte = ord(blob[0])
    if first_byte & 0x80 == 0:
        # easy one
        raw_string = blob[1:][:first_byte]
        length_determined_string = raw_string[2:][:-2]
        if len(length_determined_string) != 0:
            return length_determined_string[1:]
        return length_determined_string
    # Our string is not very long
    return ""


def is_dot_net_assembly(pe):
    return pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0


def get_assembly_guids(assembly_path):
    try:
        try:
            pe = pefile.PE(assembly_path)
        except pefile.PEFormatError:
            return None
        if not is_dot_net_assembly(pe):
            return None

        # Removed strict parsing and opted for simple searching method to support malformed assemblies
        with open(assembly_path, "rb") as assembly_file_handler:
            file_data = assembly_file_handler.read()
        for i in [file_data[l.start():] for l in re.finditer("\x42\x53\x4a\x42", file_data)]:
            try:
                if "\x42\x53\x4a\x42" not in i:
                    continue
                meta_data_offset = i.find("\x42\x53\x4a\x42")
                clr_version_length = struct.unpack("<I", i[meta_data_offset + 12:meta_data_offset + 16])[0]
                try:
                    stream_count = struct.unpack("<H", i[meta_data_offset + clr_version_length +
                                                         18:meta_data_offset + clr_version_length + 20])[0]
                except struct.error:
                    continue
                current_offset = meta_data_offset + clr_version_length + 20
                heaps = {}
                for c in xrange(stream_count):
                    offset = struct.unpack("<I", i[current_offset:current_offset + 4])[0]
                    size = struct.unpack("<I", i[current_offset + 4:current_offset + 8])[0]
                    current_offset += 8
                    name = ""
                    while "\x00" not in name:
                        name += i[current_offset:current_offset + 4]
                        current_offset += 4
                    name = name.strip("\x00")
                    # print "{0} at {1}, {2} bytes".format(name, offset, size)
                    heaps[name] = i[meta_data_offset + offset:meta_data_offset + offset + size]
                    # if len(heaps[name]) != size:
                    #    raise

                try:
                    extracted_mvid = format_guid_from_hex(heaps["#GUID"][:16].encode("hex"))
                except KeyError:
                    return {}

                tilde = heaps["#~"]

                if tilde is not None:
                    # print "Reserved: {0}".format([tilde[0:4]])
                    # print "Major: {0}".format([tilde[4:5]])
                    # print "Minor: {0}".format([tilde[5:6]])

                    # print "Heap offset indication: {0}".format([tilde[6:7]])
                    strings_heap_index_length = 2 if ord(tilde[6:7]) & 0x01 == 0x00 else 4
                    guid_heap_index_length = 2 if ord(tilde[6:7]) & 0x02 == 0x00 else 4
                    blob_heap_index_length = 2 if ord(tilde[6:7]) & 0x04 == 0x00 else 4

                    # Build row length for each type up to CustomAttr
                    row_type_widths = [
                        # 0x00 Module = Generation (2 bytes) + Name (String heap index) + Mvid (Guid heap index) +
                        # EncId (Guid heap index) + EncBaseId (Guid heap index)
                        2 + strings_heap_index_length + (guid_heap_index_length * 3),

                        # 0x01 TypeRef = ResolutionScope (ResolutionScope index) + TypeName (String heap) +
                        # TypeNamespace (String heap)
                        2 + (strings_heap_index_length * 2),
                        # 0x02 TypeDef = Flags(2 bytes) + TypeName(String heap index) +TypeNamespace(String heap index)+
                        # Extends (TypeDefOrRef index) + FieldList (index into field table) +
                        # MethodList (index into MethodDef table) + ?
                        10 + (strings_heap_index_length * 2),
                        0,  # 0x03 None
                        # 0x04 Field = Flags (2 bytes) + Name (String heap index) + Signature (Blob heap index)
                        2 + strings_heap_index_length + blob_heap_index_length,
                        0,  # 0x05 None
                        # 0x06 MethodDef = RVA(4 bytes) + ImplFlags(2 bytes) + Flags(2 bytes) + Name(String heap index)+
                        # Signature (Blob heap index) + ParamList (index to param table)
                        10 + strings_heap_index_length + blob_heap_index_length,
                        0,  # 0x07 None
                        # 0x08 Param = Flags (2 bytes) + Sequence (2 bytes) + Name (String heap index)
                        4 + strings_heap_index_length,
                        # 0x09 InterfaceImpl = Class (TypeDef index) + Interface (TypeDefOrRef index)
                        4,
                        # 0x0a MemberRef = Class(MemberRefParent) + Name(String heap index) + Signature(Blob heap index)
                        2 + strings_heap_index_length + blob_heap_index_length,
                        # 0x0b Constant = Type (?) + Parent + Value (Blob heap index)
                        4 + blob_heap_index_length,
                        # 0x0c CustomAttr = Parent + Type (CustomAttributeType) + Value (Blob heap index)
                        4 + blob_heap_index_length,
                        # Don't care about the rest
                    ]

                    # print "Reserved 0x01: {0}".format([tilde[7:8]])
                    # print "Table list: {0}".format([tilde[8:16]])

                    tables_present = [x == "1" for x in bin(struct.unpack("<Q", tilde[8:16])[0])[2:][::-1]]
                    # tables_present_count = len([a for a in tables_present if a])
                    # print "Tables present count: {0}".format(tables_present_count)

                    # print "Which tables are sorted list: {0}".format([tilde[16:24]])

                    row_counts = [0] * len(tables_present)
                    t_offset = 24
                    for index in xrange(len(tables_present)):
                        if tables_present[index]:
                            row_counts[index] = struct.unpack("<I", tilde[t_offset:t_offset + 4])[0]
                            t_offset += 4

                    for index in xrange(0x0c):
                        t_offset += row_type_widths[index] * row_counts[index]

                    for index in xrange(row_counts[0x0c]):
                        # parent_index = struct.unpack("<H", tilde[t_offset:t_offset + 2])[0]
                        # type_index = struct.unpack("<H", tilde[t_offset + 2:t_offset + 4])[0]
                        if blob_heap_index_length == 2:
                            blob_index = struct.unpack("<H", tilde[t_offset + 4:t_offset + 6])[0]
                            data_value = read_blob(heaps["#Blob"][blob_index:])
                        else:
                            blob_index = struct.unpack("<I", tilde[t_offset + 4:t_offset + 8])[0]
                            data_value = read_blob(heaps["#Blob"][blob_index:])
                        if guid_regex.match(data_value):
                            return {"mvid": extracted_mvid.lower(), "typelib_id": data_value.lower()}
                        t_offset += row_type_widths[0x0c]
                return {"mvid": extracted_mvid.lower()}
            except KeyboardInterrupt:
                raise
            except:
                pass
    except KeyboardInterrupt:
        raise
    except:
        return {}
    return {}


if __name__ == "__main__":
    from argparse import ArgumentParser

    version = "1.1.0"

    parser = ArgumentParser(
        prog=__file__,
        description="Extracts Typelib IDs and MVIDs from .NET assemblies.",
        version="%(prog)s v" + version + " by Brian Wallace (@botnet_hunter)",
        epilog="%(prog)s v" + version + " by Brian Wallace (@botnet_hunter)"
    )
    parser.add_argument('path', metavar='path', type=str, nargs='*', default=[],
                        help="Paths to files or directories to scan")
    parser.add_argument('-r', '--recursive', default=False, required=False, action='store_true',
                        help="Scan paths recursively")

    args = parser.parse_args()

    if args.path is None or len(args.path) == 0:
        if not args.stdin:
            parser.print_help()
            exit()

    from os.path import isfile, isdir, join, abspath
    from glob import iglob

    def scan_paths(paths, recursive):
        while len(paths) != 0:
            temporary_file_path = abspath(paths[0])
            del paths[0]
            if isfile(temporary_file_path):
                yield temporary_file_path, get_assembly_guids(temporary_file_path)
            elif isdir(temporary_file_path):
                for p in iglob(join(temporary_file_path, "*")):
                    p = join(temporary_file_path, p)
                    if isdir(p) and recursive:
                        paths.append(p)
                    if isfile(p):
                        yield p, get_assembly_guids(p)

    import hashlib
    for file_path, result in scan_paths(args.path, args.recursive):
        if result is None:
            continue
        try:
            typelib_id = result["typelib_id"]
        except KeyError:
            typelib_id = "None"
        try:
            mvid = result["mvid"]
        except KeyError:
            # Potentially should log these results as they should at least have an MVID
            continue

        with open(file_path, 'rb') as f:
            s = hashlib.sha256(f.read()).hexdigest()

        print "{0}\t{1}\t{2}".format(typelib_id, mvid, s)