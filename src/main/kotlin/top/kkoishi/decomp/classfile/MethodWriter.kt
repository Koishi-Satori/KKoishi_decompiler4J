package top.kkoishi.decomp.classfile

import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.ClassReader.*
import top.kkoishi.cv4j.MethodInfo
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

        @JvmStatic
        private val jvmMethodAccessFlags: Array<Pair<Int, String>> =
            arrayOf(METHOD_ACCESS_FLAG_ACC_SYNTHETIC to "synthetic ",
                METHOD_ACCESS_FLAG_ACC_STRICT to "strictfp ",
                METHOD_ACCESS_FLAG_ACC_ABSTRACT to "abstract ",
                METHOD_ACCESS_FLAG_ACC_NATIVE to "native ",
                METHOD_ACCESS_FLAG_ACC_VARARGS to "varargs ",
                METHOD_ACCESS_FLAG_ACC_BRIDGE to "bridge ",
                METHOD_ACCESS_FLAG_ACC_SYNCHRONIZED to "synchronized ",
                METHOD_PARAMETERS_ACC_FINAL to "final ",
                METHOD_ACCESS_FLAG_ACC_STATIC to "static ",
                METHOD_ACCESS_FLAG_ACC_PROTECTED to "protected ",
                METHOD_ACCESS_FLAG_ACC_PRIVATE to "private ",
                METHOD_ACCESS_FLAG_ACC_PUBLIC to "public ")

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
        fun methodAccessFlags(accessFlags: Int): String {
            var cpy = accessFlags
            val sb = StringBuilder()
            jvmMethodAccessFlags.forEach {
                with(it) {
                    if (cpy >= first) {
                        cpy -= first
                        sb.append(second)
                    }
                }
            }
            return sb.toString()
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
                    append(method.getReadableName())
                    if (lines_locals) {

                    }
                    if (instructions) {

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