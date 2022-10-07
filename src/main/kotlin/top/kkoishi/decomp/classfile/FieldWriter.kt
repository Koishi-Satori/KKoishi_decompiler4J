@file:Suppress("MemberVisibilityCanBePrivate")

package top.kkoishi.decomp.classfile

import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.ClassReader.*
import top.kkoishi.cv4j.FieldInfo
import top.kkoishi.cv4j.cp.ConstUtf8Info
import top.kkoishi.decomp.Context
import top.kkoishi.decomp.DecompileTask
import top.kkoishi.decomp.Options
import top.kkoishi.decomp.classfile.FileProcessor.Companion.parseTypeDescriptor

class FieldWriter(
    val classReader: ClassReader,
    context: Context,
    val level: Options.DisplayLevel,
    val access: Boolean,
    val signature: Boolean
) : Context() {
    val task = DecompileTask.instance(context)

    companion object {
        const val SIGNATURE_PERMISSION: Byte = 0x00
        const val SIGNATURE_HIGH: Byte = 0x01
        const val SIGNATURE_LOW: Byte = 0x03
        const val SIGNATURE_HIDE: Byte = 0x0f

        internal enum class FieldAccess constructor(val identifiedName: String, val signature: Byte = SIGNATURE_HIDE) {
            ENUM("enum", SIGNATURE_PERMISSION),
            SYNTHETIC("synthetic"),
            TRANSIENT("transient", SIGNATURE_LOW),
            VOLATILE("volatile", SIGNATURE_HIGH),
            FINAL("final", SIGNATURE_LOW),
            STATIC("static", SIGNATURE_HIGH),
            PROTECTED("protected", SIGNATURE_PERMISSION),
            PRIVATE("private", SIGNATURE_PERMISSION),
            PUBLIC("public", SIGNATURE_PERMISSION);

            companion object {
                internal fun cmp(): Comparator<FieldAccess> {
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
        internal var jvmFieldAccessFlags: Array<Pair<Int, FieldAccess>> = arrayOf(
            FIELD_ACCESS_FLAG_ACC_ENUM to FieldAccess.ENUM,
            FIELD_ACCESS_FLAG_ACC_SYNTHETIC to FieldAccess.SYNTHETIC,
            FIELD_ACCESS_FLAG_ACC_TRANSIENT to FieldAccess.TRANSIENT,
            FIELD_ACCESS_FLAG_ACC_VOLATILE to FieldAccess.VOLATILE,
            FIELD_ACCESS_FLAG_ACC_FINAL to FieldAccess.FINAL,
            FIELD_ACCESS_FLAG_ACC_STATIC to FieldAccess.STATIC,
            FIELD_ACCESS_FLAG_ACC_PROTECTED to FieldAccess.PROTECTED,
            FIELD_ACCESS_FLAG_ACC_PRIVATE to FieldAccess.PRIVATE,
            FIELD_ACCESS_FLAG_ACC_PUBLIC to FieldAccess.PUBLIC
        )

        @JvmStatic
        @Suppress("LocalVariableName")
        internal fun fieldAccessArray(accessFlags: Int): ArrayDeque<FieldAccess> {
            val res: ArrayDeque<FieldAccess> = ArrayDeque(3)
            var _accessFlags = accessFlags
            for (acc in jvmFieldAccessFlags) {
                if (_accessFlags >= acc.first) {
                    _accessFlags -= acc.first
                    res.addLast(acc.second)
                }
            }
            return res
        }

        @JvmStatic
        private fun fieldAccessFlags0(accessFlags: ArrayDeque<FieldAccess>): ArrayDeque<FieldAccess> {
            val res: ArrayDeque<FieldAccess> = ArrayDeque(accessFlags.size)
            for (acc in accessFlags) {
                if (acc.signature < MethodWriter.SIGNATURE_HIDE) {
                    res.addLast(acc)
                }
            }
            res.sortWith(FieldAccess.cmp())
            return res
        }

        @JvmStatic
        fun fieldAccessFlags(accessFlags: Int): String {
            val rest = fieldAccessFlags0(fieldAccessArray(accessFlags)).iterator()
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
        fun isAccessFlag(magic_number: Int, accessFlags: Int): Boolean {
            var cpy = accessFlags
            jvmFieldAccessFlags.forEach {
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
    }

    fun process() = classReader.fieldTable.forEach {
        with(processField(it)) {
            if (isNotEmpty())
                task.report(this)
        }
    }

    internal fun processField(field: FieldInfo): String {
        with(field) {
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
                    append(getReadableName()).append(';')
                    if (signature)
                        append("\n\t").append("Descriptor: ").append(getUtf(descriptorIndex))
                    if (access) {
                        append("\n\tField Access Flags(0X").append(accessFlags.toString(16)).append("):")
                        for (acc in fieldAccessArray(accessFlags)) {
                            append(' ').append("ACC_").append(acc.name)
                        }
                    }
                    return toString()
                }
            }
        }
        return ""
    }

    private fun getUtf(index: Int): String = (classReader.cpInfo[index - 1] as ConstUtf8Info).utf8

    private fun FieldInfo.getJVMName() = "${getUtf(nameIndex)}${getUtf(descriptorIndex)}"

    private fun FieldInfo.getReadableName(): String {
        val descriptor = parseTypeDescriptor(getUtf(descriptorIndex))
        return fieldAccessFlags(accessFlags) + descriptor.first + " " + getUtf(nameIndex)
    }

    fun size() = classReader.fieldTable.size
}