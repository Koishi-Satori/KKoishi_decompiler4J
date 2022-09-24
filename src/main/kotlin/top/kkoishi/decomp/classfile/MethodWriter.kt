package top.kkoishi.decomp.classfile

import top.kkoishi.cv4j.Bytecodes
import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.ClassReader.*
import top.kkoishi.cv4j.MethodInfo
import top.kkoishi.cv4j.attr.CodeAttribute
import top.kkoishi.cv4j.cp.ConstUtf8Info
import top.kkoishi.decomp.Context
import top.kkoishi.decomp.DecompileTask
import top.kkoishi.decomp.Options

@Suppress("RedundantEmptyInitializerBlock")
class MethodWriter(
    val classReader: ClassReader,
    context: Context,
    val level: Options.DisplayLevel,
    val lines_locals: Boolean,
    val instructions: Boolean,
) : Context() {
    companion object {
        const val SIGNATURE_PERMISSION: Byte = 0x00
        const val SIGNATURE_HIGH: Byte = 0x01
        const val SIGNATURE_MID: Byte = 0x02
        const val SIGNATURE_LOW: Byte = 0x03
        const val SIGNATURE_HIDE: Byte = 0x0f

        internal enum class MethodAccess(val identifiedName: String, val signature: Byte) {
            SYNTHETIC("synthetic", SIGNATURE_HIDE),
            STRICT("strictfp", SIGNATURE_LOW),
            ABSTRACT("abstract", SIGNATURE_MID),
            NATIVE("native", SIGNATURE_MID),
            VARARGS("varargs", SIGNATURE_HIDE),
            BRIDGE("bridge", SIGNATURE_HIDE),
            SYNCHRONIZED("synchronized", SIGNATURE_LOW),
            FINAL("final", SIGNATURE_MID),
            STATIC("static", SIGNATURE_MID),
            PROTECTED("protected", SIGNATURE_HIGH),
            PRIVATE("private", SIGNATURE_HIGH),
            PUBLIC("public", SIGNATURE_HIGH);

            companion object {
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
        with(classReader) {
            val requiredLevel: Options.DisplayLevel =
                if (isAccessFlag(METHOD_ACCESS_FLAG_ACC_PUBLIC, method.accessFlags))
                    Options.DisplayLevel.PUBLIC
                else if (isAccessFlag(METHOD_ACCESS_FLAG_ACC_PROTECTED, method.accessFlags))
                    Options.DisplayLevel.PROTECTED
                else if (isAccessFlag(METHOD_ACCESS_FLAG_ACC_PRIVATE, method.accessFlags))
                    Options.DisplayLevel.PRIVATE
                else Options.DisplayLevel.PACKAGE
            if (level.ordinal >= requiredLevel.ordinal) {
                val sb = StringBuilder()
                with(sb) {
                    append(method.getReadableName()).append("\n\t")
                    append("Method Access Flags:\n")
                    methodAccessArray(method.accessFlags).forEach { append("\t\tACC_").append(it.name).append('\n') }
                    // Find CodeAttribute first.
                    var codeAttr: CodeAttribute? = null
                    for (attribute in method.attributes) {
                        if (getUtf(attribute.attributeNameIndex) == "Code") {
                            codeAttr = attribute as CodeAttribute
                            break
                        }
                    }
                    if (codeAttr == null) {
                        throw ExceptionInInitializerError("Can not access the CodeAttribute in method ${method.getJVMName()}.")
                    }
                    if (instructions) {
                        val instructions = Bytecodes.getJvm_instructions_array()
                        for (b in codeAttr.code) {
                            //TODO: finish read.
                        }
                    }
                    if (lines_locals) {

                    }
                    return sb.toString()
                }
            }
        }
        return ""
    }

    private fun getUtf(index: Int): String = (classReader.cpInfo[index - 1] as ConstUtf8Info).utf8

    private fun MethodInfo.getJVMName(): String = "${getUtf(nameIndex)}${getUtf(descriptorIndex)}"

    private fun MethodInfo.getReadableName(): String {
        val descriptor = FileProcessor.parseTypeDescriptor(getUtf(descriptorIndex))
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