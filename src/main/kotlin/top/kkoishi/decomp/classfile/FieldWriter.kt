package top.kkoishi.decomp.classfile

import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.ClassReader.FIELD_ACCESS_FLAG_ACC_ENUM
import top.kkoishi.decomp.Context
import top.kkoishi.decomp.DecompileTask
import top.kkoishi.decomp.Options

class FieldWriter(
    val classReader: ClassReader,
    context: Context,
    val level: Options.DisplayLevel,
) : Context() {
    val task = DecompileTask.instance(context)

    companion object {
        @JvmStatic
        val jvmFieldAccessFlags: Array<Pair<Int, String>> = arrayOf(FIELD_ACCESS_FLAG_ACC_ENUM to "enum ")
    }
}