import json

class FileWrapper:
    def __init__(self, file):
        self.file = file

    def read(self, count):
        return self.file.read(count)

    def read_int(self, count):
        return int.from_bytes(self.file.read(count))

def read_verif_types(file, count):
    result = []
    for _ in range(count):
        tag = file.read_int(1)
        match tag:
            case 0:
                result.append("Top")
            case 1:
                result.append("Integer")
            case 2:
                result.append("Float")
            case 3:
                result.append("Double")
            case 4:
                result.append("Long")
            case 5:
                result.append("Null")
            case 6:
                result.append("UninitializedThis")
            case 7:
                cpool_index = file.read_int(2)
                class_name_index = clazz["constant_pool"][cpool_index]["name_index"]
                class_name = clazz["constant_pool"][class_name_index]["bytes"].decode()
                result.append(f"class {class_name}")
            case 8:
                result.append(f"Uninitialized offset={file.read_int(2)}")
            case _:
                assert False, f"Unknown local tag {tag}"
    return result

def read_attrs(file, clazz, count):
    result = []
    for _ in range(count):
        attr = {}
        attr["name"] = clazz["constant_pool"][file.read_int(2)]["bytes"].decode()

        attr_len = file.read_int(4)
        match attr["name"]:
            case "Code":
                attr["max_stack"] = file.read_int(2)
                attr["max_locals"] = file.read_int(2)
                code_len = file.read_int(4)
                file.read(code_len)
                attr["code"] = f"{code_len} bytes"
                attr["exception_table"] = []
                for _ in range(file.read_int(2)):
                    exc = {}
                    exc["start_pc"] = file.read_int(2)
                    exc["end_pc"] = file.read_int(2)
                    exc["handler_pc"] = file.read_int(2)
                    exc["catch_type"] = file.read_int(2)
                    attr["exception_table"].append(exc)
                attr["attributes"] = read_attrs(file, clazz, file.read_int(2))

            case "StackMapTable":
                attr["entries"] = []
                for _ in range(file.read_int(2)):
                    entry = {}
                    frame_type = file.read_int(1)
                    match frame_type:
                        case t if 0 <= t and t <= 63:
                            entry["name"] = "same_frame"
                            entry["offset_delta"] = frame_type

                        case 255:
                            entry["name"] = "full_frame"
                            entry["offset_delta"] = file.read_int(2)
                            entry["locals"] = read_verif_types(file, file.read_int(2))
                            entry["stack"] = read_verif_types(file, file.read_int(2))

                        case _:
                            assert False, f"Uknown frame type {frame_type}"
                    attr["entries"].append(entry)

            case _:
                file.read(attr_len)

        result.append(attr)
    return result


clazz = {}
with open("Test.class", "rb") as file:
    f = FileWrapper(file)
    assert f.read_int(4) == 0xcafebabe

    clazz["minor"] = f.read_int(2)
    clazz["major"] = f.read_int(2)
    clazz["constant_pool"] = {}
    cp_count = f.read_int(2)
    i = 1
    while i < cp_count:
        tag = f.read_int(1)
        constant = {}
        match tag:
            case 1:
                constant["tag"] = "Utf-8"
                constant["bytes"] = f.read(f.read_int(2))
            case 3:
                constant["tag"] = "Integer"
                constant["bytes"] = {f.read(4)}
            case 4:
                constant["tag"] = "Float"
                constant["bytes"] = {f.read(4)}
            case 5:
                constant["tag"] = "Long"
                constant["high_bytes"] = {f.read(4)}
                constant["low_bytes"] = {f.read(4)}
                i += 1
            case 6:
                constant["tag"] = "Double"
                constant["high_bytes"] = f.read(4)
                constant["low_bytes"] = f.read(4)
                i += 1
            case 7:
                constant["tag"] = "Class"
                constant["name_index"] = f.read_int(2)
            case 8:
                constant["tag"] = "String"
                constant["string_index"] = f.read_int(2)
            case 9:
                constant["tag"] = "FieldRef"
                constant["class_index"] = f.read_int(2)
                constant["name_and_type_index"] = f.read_int(2)
            case 10:
                constant["tag"] = "MethodRef"
                constant["class_index"] = f.read_int(2)
                constant["name_and_type_index"] = f.read_int(2)
            case 12:
                constant["tag"] = "NameAndType"
                constant["name_index"] = f.read_int(2)
                constant["descriptor_index"] = f.read_int(2)
            case _:
                assert False, f"Unknown constant tag {tag}"
        clazz["constant_pool"][i] = constant
        i += 1

    clazz["access_flags"] = f.read(2).hex()
    clazz["this_class"] = f.read_int(2)
    clazz["super_class"] = f.read_int(2)

    clazz["interfaces"] = []
    for _ in range(f.read_int(2)):
        clazz["interfaces"].append(f.read_int(2))

    clazz["fields"] = []
    for _ in range(f.read_int(2)):
        field = {}
        field["access_flags"] = f.read(2).hex()
        field["name_index"] = f.read_int(2)
        field["descriptor_index"] = f.read_int(2)
        field["attributes"] = read_attrs(f, clazz, f.read_int(2))
        clazz["fields"].append(field)

    clazz["methods"] = []
    for _ in range(f.read_int(2)):
        method = {}
        method["access_flags"] = f.read(2).hex()
        method["name_index"] = f.read_int(2)
        method["descriptor_index"] = f.read_int(2)
        method["attributes"] = read_attrs(f, clazz, f.read_int(2))
        clazz["methods"].append(method)

    clazz["attributes"] = read_attrs(f, clazz, f.read_int(2))



print("CLASS ################################################################")
print("minor:", clazz["minor"])
print("major:", clazz["major"])
print("this_class:", clazz["this_class"])
print("super_class:", clazz["super_class"])
print("access_flags:", clazz["access_flags"])
print("----------------------------------------------------------------------")

print("\nCONSTANT_POOL ########################################################")
for idx, c in clazz["constant_pool"].items():
    info = ""
    for el in list(c.items()):
        if el[0] != "tag":
            info += f"{el[0]}={el[1]}, "
    print("#%-3d %-18s %s" % (idx, c["tag"], info))
print("----------------------------------------------------------------------")

print("\nMETHODS ##############################################################")
print(json.dumps(clazz["methods"], indent=2))

    # assert read_int(f, 2) == 0 # interfaces
    # assert read_int(f, 2) == 0 # fields
    #
    # print("\nMETHOD ---------------------------------------------------------------")
    # assert read_int(f, 2) == 1 # one method
    # print("access_flags:", read_int(f, 2));
    # print("name_index:", read_int(f, 2));
    # print("descriptor_index:", read_int(f, 2));
    # assert read_int(f, 2) == 1 # 1 attributes
    #
    # print("CODE -----------------------------------------------------------")
    # print("attribute_name_index:", read_int(f, 2));
    # print("attribute_length:", read_int(f, 4))
    # print("max_stack:", read_int(f, 2));
    # print("max_locals:", read_int(f, 2));
    # print("code:", f.read(read_int(f, 4)))
    # assert read_int(f, 2) == 0 # exception table length
    # assert read_int(f, 2) == 2 # stack map table attribute
    # attribute_info attributes[attributes_count];

    # attributes_count = read_int(f, 2)
    # print("attributes_count:", attributes_count);
    # assert attributes_count == 1
    # print("code_name_index:", read_int(f, 2))
