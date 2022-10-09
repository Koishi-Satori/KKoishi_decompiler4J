package top.kkoishi.decomp.classfile

import top.kkoishi.cv4j.Attribute_info
import top.kkoishi.cv4j.Bytecodes.*
import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.ClassReader.*
import top.kkoishi.cv4j.ConstPoolInfo
import top.kkoishi.cv4j.MethodInfo
import top.kkoishi.cv4j.attr.CodeAttribute
import top.kkoishi.cv4j.attr.LineNumberTableAttribute
import top.kkoishi.cv4j.attr.LocalVariableTableAttribute
import top.kkoishi.cv4j.cp.*
import top.kkoishi.decomp.Context
import top.kkoishi.decomp.DecompileTask
import top.kkoishi.decomp.Options
import top.kkoishi.decomp.Utils
import top.kkoishi.decomp.Utils.length
import top.kkoishi.decomp.classfile.FileProcessor.Companion.parseTypeDescriptor
import kotlin.Comparator
import kotlin.collections.ArrayDeque

@Suppress("RedundantEmptyInitializerBlock")
class MethodWriter(
    val classReader: ClassReader,
    context: Context,
    val level: Options.DisplayLevel,
    val lines_locals: Boolean,
    val instructions: Boolean,
    val access: Boolean,
    val signature: Boolean,
) : Context() {
    companion object {
        const val SIGNATURE_PERMISSION: Byte = 0x00
        const val SIGNATURE_HIGH: Byte = 0x01
        const val SIGNATURE_MID: Byte = 0x02
        const val SIGNATURE_LOW: Byte = 0x03
        const val SIGNATURE_HIDE: Byte = 0x0f
        const val GOTO_OFFSET_BASE = 0X10000

        internal enum class MethodAccess constructor(val identifiedName: String, val signature: Byte = SIGNATURE_HIDE) {
            SYNTHETIC("synthetic"),
            STRICT("strictfp", SIGNATURE_LOW),
            ABSTRACT("abstract", SIGNATURE_HIGH),
            NATIVE("native", SIGNATURE_MID),
            VARARGS("varargs"),
            BRIDGE("bridge"),
            SYNCHRONIZED("synchronized", SIGNATURE_MID),
            FINAL("final", SIGNATURE_HIGH),
            STATIC("static", SIGNATURE_HIGH),
            PROTECTED("protected", SIGNATURE_PERMISSION),
            PRIVATE("private", SIGNATURE_PERMISSION),
            PUBLIC("public", SIGNATURE_PERMISSION);

            companion object {
                @JvmStatic
                internal fun cmp(): Comparator<MethodAccess> {
                    return Comparator { o1, o2 ->
                        if (o1.signature == o2.signature)
                            o1.ordinal - o2.ordinal
                        else
                            o1.signature - o2.signature
                    }
                }
            }
        }

        @JvmStatic
        private val jvmMethodAccessFlags: Array<Pair<Int, MethodAccess>> =
            arrayOf(METHOD_ACCESS_FLAG_ACC_SYNTHETIC to MethodAccess.SYNTHETIC,
                METHOD_ACCESS_FLAG_ACC_STRICT to MethodAccess.STRICT,
                METHOD_ACCESS_FLAG_ACC_ABSTRACT to MethodAccess.ABSTRACT,
                METHOD_ACCESS_FLAG_ACC_NATIVE to MethodAccess.NATIVE,
                METHOD_ACCESS_FLAG_ACC_VARARGS to MethodAccess.VARARGS,
                METHOD_ACCESS_FLAG_ACC_BRIDGE to MethodAccess.BRIDGE,
                METHOD_ACCESS_FLAG_ACC_SYNCHRONIZED to MethodAccess.SYNCHRONIZED,
                METHOD_PARAMETERS_ACC_FINAL to MethodAccess.FINAL,
                METHOD_ACCESS_FLAG_ACC_STATIC to MethodAccess.STATIC,
                METHOD_ACCESS_FLAG_ACC_PROTECTED to MethodAccess.PROTECTED,
                METHOD_ACCESS_FLAG_ACC_PRIVATE to MethodAccess.PRIVATE,
                METHOD_ACCESS_FLAG_ACC_PUBLIC to MethodAccess.PUBLIC)


        @JvmStatic
        fun isAccessFlag(magic_number: Int, accessFlags: Int): Boolean {
            var cpy = accessFlags
            jvmMethodAccessFlags.forEach {
                with(it) {
                    if (cpy >= first) {
                        if (first == magic_number) {
                            return true
                        }
                        cpy -= first
                    }
                }
            }
            return false
        }

        @JvmStatic
        @Suppress("LocalVariableName")
        internal fun methodAccessArray(accessFlags: Int): ArrayDeque<MethodAccess> {
            val res: ArrayDeque<MethodAccess> = ArrayDeque(5)
            var _accessFlags = accessFlags
            for (acc in jvmMethodAccessFlags) {
                if (_accessFlags >= acc.first) {
                    _accessFlags -= acc.first
                    res.addLast(acc.second)
                }
            }
            return res
        }

        @JvmStatic
        private fun methodAccessFlags0(accessFlags: ArrayDeque<MethodAccess>): ArrayDeque<MethodAccess> {
            val res: ArrayDeque<MethodAccess> = ArrayDeque(accessFlags.size)
            for (acc in accessFlags) {
                if (acc.signature < SIGNATURE_HIDE) {
                    res.addLast(acc)
                }
            }
            res.sortWith(MethodAccess.cmp())
            return res
        }

        @JvmStatic
        fun methodAccessFlags(accessFlags: Int): String {
            val rest = methodAccessFlags0(methodAccessArray(accessFlags)).iterator()
            if (!rest.hasNext()) {
                return ""
            }
            val buf = StringBuilder()
            while (true) {
                buf.append(rest.next().identifiedName).append(' ')
                if (!rest.hasNext())
                    return buf.toString()
            }
        }

        @JvmStatic
        @Suppress("UNCHECKED_CAST")
        fun ConstNameAndTypeInfo.intData(): IntArray {
            with(data() as Array<ByteArray>) {
                val data = IntArray(2)
                data[0] = toInt(this[0])
                data[1] = toInt(this[1])
                return data
            }
        }

        @JvmStatic
        fun parseInstruction(
            v: IndexedValue<Byte>,
            rest: Iterator<IndexedValue<Byte>>,
            length: Int,
            inst_pos: Int,
            const_pool: ArrayList<ConstPoolInfo>,
        ): String {
            val inst: Instruction = forInstruction(v.value)
            val buf = StringBuilder("\t\t").append(Utils.formatNumber(inst_pos, length.length(), false, "", ' '))
                .append(": ").append(inst.name().lowercase())
            val other_bytes = inst.otherBytes()
            if (other_bytes > 0) {
                if (other_bytes <= 2) {
                    val intBuf = ByteArray(other_bytes)
                    for (i in 0 until other_bytes)
                        intBuf[i] = rest.next().value
                    if (inst.instruction() == GOTO || inst.instruction() == GOTO_W) {
                        val offset = toInt(intBuf) - GOTO_OFFSET_BASE
                        buf.append(' ').append(v.index + offset)
                    } else {
                        val index = toInt(intBuf)
                        buf.append(' ')
                        // Get the value which the index pointed to.
                        // TODO
                        fun getClassUtf(classInfoIndex: Int): String =
                            (const_pool[(const_pool[classInfoIndex] as ConstClassInfo).index - 1] as ConstUtf8Info).utf8

                        fun getFieldUtf(fieldInfoIndex: Int): String {
                            @Suppress("UNCHECKED_CAST")
                            with((const_pool[fieldInfoIndex] as ConstFieldrefInfo).data() as Array<ByteArray>) {
                                val nameAndType = (const_pool[toInt(this[1]) - 1] as ConstNameAndTypeInfo).intData()
                                return getClassUtf(toInt(this[0]) - 1) + '.' +
                                        (const_pool[nameAndType[0] - 1] as ConstUtf8Info).utf8 + ':' +
                                        (const_pool[nameAndType[1] - 1] as ConstUtf8Info).utf8
                            }
                        }

                        fun getMethodUtf(methodInfoIndex: Int): String {
                            @Suppress("UNCHECKED_CAST")
                            with(const_pool[methodInfoIndex].data() as Array<ByteArray>) {
                                val nameAndType = (const_pool[toInt(this[1]) - 1] as ConstNameAndTypeInfo).intData()
                                return getClassUtf(toInt(this[0]) - 1) + '.' +
                                        (const_pool[nameAndType[0] - 1] as ConstUtf8Info).utf8 + ':' +
                                        (const_pool[nameAndType[1] - 1] as ConstUtf8Info).utf8
                            }
                        }

                        fun getInterfaceMethodInfoUtf(interfaceMethodIndex: Int): String {
                            @Suppress("UNCHECKED_CAST")
                            with((const_pool[interfaceMethodIndex] as ConstInterfaceMethodrefInfo).data() as Array<ByteArray>) {
                                val nameAndType = (const_pool[toInt(this[1]) - 1] as ConstNameAndTypeInfo).intData()
                                return getClassUtf(toInt(this[0]) - 1) + '.' +
                                        (const_pool[nameAndType[0] - 1] as ConstUtf8Info).utf8 + ':' +
                                        (const_pool[nameAndType[1] - 1] as ConstUtf8Info).utf8
                            }
                        }

                        when (inst.instruction()) {
                            ANEWARRAY, CHECKCAST, INSTANCEOF ->
                                buf.append('#').append(index).append("\t//").append(getClassUtf(index - 1))
                            GETFIELD, GETSTATIC ->
                                buf.append('#').append(index).append("\t//").append(getFieldUtf(index - 1))
                            in IF_ICMPEQ..IF_ICMPNE, in IFEQ..IFLE, IFNONNULL, IFNULL ->
                                buf.append(index + inst_pos)
                            INVOKEDYNAMIC, INVOKEVIRTUAL, INVOKESPECIAL, INVOKESTATIC ->
                                buf.append('#').append(index).append("\t//").append(getMethodUtf(index - 1))
                            INVOKEINTERFACE ->
                                buf.append('#').append(index).append("\t//").append(getInterfaceMethodInfoUtf(index))
                            else -> buf.append(index)
                        }
                    }
                    return buf.append('\n').toString()
                }
            } else if (other_bytes == 0) {
                // Ignore this branch.
            } else {
                var len: Int
                // Calculate the bytes count of special instructions which
                // have variable other_bytes count.
                // The tableswitch and lookupswitch instruction should contain
                // 0~3 bytes padding to make sure the start indexes of default_index,
                // other indexes and offsets are the multiple of four.
                //
                // Tableswitch: default(u4, the default brance jump offset),
                // high(u4), low(u4), offsets[high -low + 1]. Every offset
                // contains jump_offset(u4).
                //
                // Lookupswitch: default(u4, the default brance jump offset),
                // npairs_count(u4), npair[npairs_count]. Every npair contains
                // switch_value and jump_offset(all in u4).
                //
                // Wide: opcode(u1) + other_bytes.
                // opcode=iinc->4 other_bytes
                // iload, fload, aload, lload, dload, istore, fstore, astore,
                // lstore, dstore, or ret: 2 other_bytes
                when (v.value) {
                    LOOKUPSWITCH -> {
                        len = (length - v.index) % 4
                        for (ignore in 0 until len)
                            rest.next()
                        val intBuf = ByteArray(4)
                        for (i in 0..3)
                            intBuf[i] = rest.next().value
                        len = toInt(intBuf) - 1
                        // Parse switch_value and jump_offset
                        for (ignore in 0..len) {
                            for (i in 0..3)
                                intBuf[i] = rest.next().value
                            val switch_value = toInt(intBuf)
                            for (i in 0..3)
                                intBuf[i] = rest.next().value
                            val jump_offset = toInt(intBuf)
                            buf.append("\n\t\t\t").append(switch_value).append(":  #").append(jump_offset)
                        }
                    }
                    TABLESWITCH -> {
                        len = (length - v.index) % 4
                        for (ignore in 0 until len)
                            rest.next()
                        val intBuf = ByteArray(4)
                        for (i in 0..3)
                            intBuf[i] = rest.next().value
                        val high: Int = toInt(intBuf)
                        for (i in 0..3)
                            intBuf[i] = rest.next().value
                        val low: Int = toInt(intBuf)
                        // Use local var len to store the last jump_offset
                        len = -1
                        for (i in 0..(high - low)) {
                            for (j in 0..3)
                                intBuf[j] = rest.next().value
                            val jump_offset = toInt(intBuf)
                            if (len != jump_offset) {
                                len = jump_offset
                                buf.append("\n\t\t\t").append(i + low).append(":  #").append(jump_offset)
                            }
                        }
                    }
                    WIDE -> {
                        val opcode = forInstruction(rest.next().value)
                        val intBuf = ByteArray(2)
                        intBuf[0] = rest.next().value
                        intBuf[1] = rest.next().value
                        buf.append("\t#").append(toInt(intBuf)).append('\t')
                        if (opcode.instruction() == IINC) {
                            intBuf[0] = rest.next().value
                            intBuf[1] = rest.next().value
                            buf.append(toInt(intBuf))
                        }
                    }
                }
            }
            return buf.append('\n').toString()
        }
    }

    val task = DecompileTask.instance(context)

    init {
        // finish later.
    }

    fun process() = classReader.methodTable.forEach {
        with(processMethod(it)) {
            if (this.isNotEmpty())
                task.report(this)
        }
    }

    @Suppress("MemberVisibilityCanBePrivate")
    internal fun processMethod(method: MethodInfo): String {
        with(method) {
            val requiredLevel: Options.DisplayLevel =
                if (isAccessFlag(METHOD_ACCESS_FLAG_ACC_PUBLIC, accessFlags))
                    Options.DisplayLevel.PUBLIC
                else if (isAccessFlag(METHOD_ACCESS_FLAG_ACC_PROTECTED, accessFlags))
                    Options.DisplayLevel.PROTECTED
                else if (isAccessFlag(METHOD_ACCESS_FLAG_ACC_PRIVATE, accessFlags))
                    Options.DisplayLevel.PRIVATE
                else Options.DisplayLevel.PACKAGE
            if (level.ordinal >= requiredLevel.ordinal) {
                with(StringBuilder()) {
                    append(getReadableName())
                    if (signature)
                        append("\n\t").append("Descriptor: ").append(getUtf(descriptorIndex))
                    if (access) {
                        append("\n\tMethod Access Flags(").append(Utils.formatNumber(accessFlags, 4)).append("):")
                        for (acc in methodAccessArray(accessFlags))
                            append(' ').append("ACC_").append(acc.name)
                    }
                    translateCodeAttribute(findCodeAttribute(method), this)
                    translateMethodAttributes(method, this)
                    return toString()
                }
            }
        }
        return ""
    }

    private fun translateCodeAttribute(code: CodeAttribute?, buf: StringBuilder) {
        if (code == null)
            return
        if (instructions) {
            val rest = code.code.withIndex().iterator()
            if (rest.hasNext()) {
                buf.append("\n\tCode:\n")
                var index = 0
                while (rest.hasNext())
                    buf.append(parseInstruction(rest.next(), rest, code.code.size, index++, classReader.cpInfo))
            }
        }
        if (lines_locals) {
            for (attr in code.attributes)
                translateCodeAttributeTable(attr, buf)
        }
    }

    private fun translateCodeAttributeTable(attr: Attribute_info, buf: StringBuilder) {
        when (getUtf(attr.attributeNameIndex)) {
            "LineNumberTable" -> {
                buf.append("\tLineNumber Table:")
                for (ln in (attr as LineNumberTableAttribute).lineNumberTable) {
                    buf.append('\n').append("\t\tline ").append(ln.lineNumber).append(": ").append(ln.startPc)
                }
            }
            "LocalVariableTable" -> {
                for (lv in (attr as LocalVariableTableAttribute).localVariables) {

                }
            }
        }
    }

    private fun translateMethodAttributes(method: MethodInfo, buf: StringBuilder) {
        method.attributes
    }

    private fun findCodeAttribute(method: MethodInfo): CodeAttribute? {
        var codeAttr: CodeAttribute? = null
        for (attribute in method.attributes) {
            if (getUtf(attribute.attributeNameIndex) == "Code") {
                codeAttr = attribute as CodeAttribute
                break
            }
        }
        if (codeAttr == null && !isAccessFlag(METHOD_ACCESS_FLAG_ACC_NATIVE, method.accessFlags) && !isAccessFlag(
                METHOD_ACCESS_FLAG_ACC_ABSTRACT, method.accessFlags)
        )
            throw ExceptionInInitializerError("Can not access the CodeAttribute in method ${method.getJVMName()}.")
        return codeAttr
    }

    private fun getUtf(index: Int): String = (classReader.cpInfo[index - 1] as ConstUtf8Info).utf8

    private fun MethodInfo.getJVMName(): String = "${getUtf(nameIndex)}${getUtf(descriptorIndex)}"

    private fun MethodInfo.getReadableName(): String {
        val descriptor = parseTypeDescriptor(getUtf(descriptorIndex))
        return methodAccessFlags(accessFlags) + descriptor.second + " " + getUtf(nameIndex) + descriptor.first
    }

    fun indexOf(full_qualified_name: String): Int {
        for ((index, info) in classReader.methodTable.withIndex()) {
            if (info.getJVMName() == full_qualified_name)
                return index
        }
        return -1
    }

    fun size(): Int = classReader.methodsCount
}