package top.kkoishi.decomp.classfile

import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.ClassReader.toInt
import top.kkoishi.cv4j.ConstPoolInfo
import top.kkoishi.cv4j.ConstPoolInfo.*
import top.kkoishi.cv4j.DecompilerException
import top.kkoishi.cv4j.attr.InnerClassAttribute
import top.kkoishi.cv4j.attr.SourceFileAttribute
import top.kkoishi.cv4j.cp.ConstClassInfo
import top.kkoishi.cv4j.cp.ConstUtf8Info
import top.kkoishi.decomp.*
import java.nio.file.Path
import kotlin.io.path.getLastModifiedTime
import kotlin.io.path.readBytes
import kotlin.jvm.Throws

class FileProcessor(val context: Context) {
    companion object {
        @JvmStatic
        var processorOptions: Array<Option> = arrayOf(
            object : Option(true, "-cp", "-classpath") {
                override fun process(task: DecompileTask, opt: String, arg: String?) {
                    TODO("Not yet implemented")
                }
            }
        )

        @JvmStatic
        fun main(args: Array<String>) {
            println(parseTypeDescriptor("([[IIJLjava/lang/String;[B)V"))
            println(parseTypeDescriptor("[[Lsun.misc.Unsafe"))
        }

        /**
         * Parse the type descriptor like V/(IJ)V.
         *
         * For the first type of parameter, the second field of return value will be null.
         *
         * And for the second type of parameter, the second one will be non-null.
         *
         * @param jvmType type descriptor.
         * @return full name like void, Pair((int, long), void).
         */
        @JvmStatic
        @Throws(DecompilerException::class)
        fun parseTypeDescriptor(jvmType: String): Pair<String, String?> {
            val rest = jvmType.iterator()
            if (rest.hasNext()) {
                val first = rest.nextChar()
                fun Char.parseImpl(rest: CharIterator): String {
                    return when (this) {
                        // Full qualified name.
                        'L' -> {
                            val buf = StringBuilder()
                            while (rest.hasNext()) {
                                val lookup = rest.nextChar()
                                if (lookup == ';') {
                                    buf.append(';')
                                    break
                                } else if (lookup == '/')
                                    buf.append('.')
                                else
                                    buf.append(lookup)
                            }
                            if (buf.last() != ';')
                                throw DecompilerException("The class full qualified name $buf is invalid.")
                            buf.deleteAt(buf.length - 1).toString()
                        }
                        'I' -> "int"
                        'J' -> "long"
                        'V' -> "void"
                        'B' -> "byte"
                        'D' -> "double"
                        'F' -> "float"
                        'S' -> "short"
                        'Z' -> "boolean"
                        '[' -> {
                            if (rest.hasNext())
                                "${rest.nextChar().parseImpl(rest)}[]"
                            else
                                throw DecompilerException("The array descriptor is invalid.")
                        }
                        else -> throw DecompilerException("The represent char is invalid.")
                    }
                }
                if (first == '(') {
                    // Consider the second case.
                    if (rest.hasNext()) {
                        val buf = StringBuilder("(")
                        while (rest.hasNext()) {
                            val lookup = rest.nextChar()
                            if (lookup == ')') {
                                if (buf.last() != '(') {
                                    val last = buf.length
                                    buf.deleteRange(last - 2, last)
                                }
                                buf.append(')')
                                break
                            }
                            buf.append(lookup.parseImpl(rest)).append(", ")
                        }
                        if (buf.last() == ')' && rest.hasNext()) {
                            return buf.toString() to rest.nextChar().parseImpl(rest)
                        }
                    }
                    throw DecompilerException("The quote of descriptor is not closed or there is no return type descriptor.")
                } else
                    return first.parseImpl(rest) to null
            }
            throw DecompilerException("The descriptor is empty!")
        }

        @JvmStatic
        internal val constantsNames: Array<String> = arrayOf("",
            "Utf8               ",
            "",
            "Integer            ",
            "Float              ",
            "Long               ",
            "Double             ",
            "Class              ",
            "String             ",
            "FieldRef           ",
            "MethodRef          ",
            "Interface MethodRef",
            "NameAndType        ",
            "MethodHandle       ",
            "MethodType         ",
            "Dynamic            ",
            "Invoke Dynamic     ",
            "Module             ",
            "Package            ")

        @JvmStatic
        fun ConstPoolInfo.report(index: Int, context: ClassReader): String {
            val sb = StringBuilder("\t#")
            if (index < 10)
                sb.append("0")
            sb.append(index).append(" = ").append(constantsNames[this.tag().toInt()]).append("\t\t")
            when (this.tag()) {
                CONSTANT_UTF8_INFO -> sb.append((this as ConstUtf8Info).utf8)
                CONSTANT_INTEGER_INFO -> sb.append(toInt(this.data() as ByteArray))
                CONSTANT_FLOAT_INFO -> sb.append(Float.fromBits(toInt(this.data() as ByteArray)))
                CONSTANT_LONG_INFO -> sb.append((this.data() as ByteArray).toLong())
                CONSTANT_DOUBLE_INFO -> sb.append(Double.fromBits((this.data() as ByteArray).toLong()))
                CONSTANT_CLASS_INFO -> {
                    val i = (this.data() as ByteArray).toShort().toInt()
                    sb.append('#').append(i).append("\t\t\t//").append((context.cpInfo[i] as ConstUtf8Info).utf8)
                }
                CONSTANT_STRING_INFO -> sb.append((context.cpInfo[(this.data() as ByteArray).toShort()
                    .toInt()] as ConstUtf8Info).utf8)
                CONSTANT_NAME_AND_TYPE_INFO -> {
                    @Suppress("UNCHECKED_CAST") val data = this.data() as Array<ByteArray>
                    val nameIndex = data[0].toShort().toInt()
                    val descriptorIndex = data[1].toShort().toInt()
                    sb.append('#').append(nameIndex).append('#')
                        .append(descriptorIndex).append("\t\t\t//")
                        .append((context.cpInfo[nameIndex - 1] as ConstUtf8Info).utf8)
                        .append((context.cpInfo[descriptorIndex - 1] as ConstUtf8Info).utf8)
                }
                CONSTANT_FIELDREF_INFO, CONSTANT_METHODREF_INFO, CONSTANT_INTERFACE_METHODREF -> {
                    // Report the CONSTANT_Class_info and CONSTANT_NameAndType_info.
                    @Suppress("UNCHECKED_CAST") val data = this.data() as Array<ByteArray>
                    val classIndex = data[0].toShort().toInt()
                    val nameAndTypeIndex = data[1].toShort().toInt()
                    sb.append('#').append(classIndex).append(".#")
                        .append(nameAndTypeIndex).append("\t\t\t//")
                    with(context) {
                        val classInfo = cpInfo[classIndex - 1]
                        @Suppress("UNCHECKED_CAST") val datum =
                            cpInfo[nameAndTypeIndex - 1].data() as Array<ByteArray>
                        sb.append((cpInfo[(classInfo.data() as ByteArray).toShort().toInt() - 1]
                                as ConstUtf8Info).utf8).append('.')
                            .append((cpInfo[datum[0].toShort().toInt() - 1] as ConstUtf8Info).utf8)
                            .append('.').append((cpInfo[datum[1].toShort().toInt() - 1]
                                    as ConstUtf8Info).utf8)
                    }
                }
                CONSTANT_METHOD_HANDLE_INFO -> {

                }
                CONSTANT_METHOD_TYPE_INFO -> {
                    val descriptorIndex = (this.data() as ByteArray).toShort().toInt()
                    sb.append('#').append(descriptorIndex).append("\t\t\t//")
                        .append((context.cpInfo[descriptorIndex - 1] as ConstUtf8Info).utf8)
                }
                CONSTANT_DYNAMIC -> {

                }
                CONSTANT_INVOKE_DYNAMIC_INFO -> {

                }
                CONSTANT_MODULE, CONSTANT_PACKAGE -> {
                    val nameIndex = (this.data() as ByteArray).toShort().toInt()
                    sb.append('#').append(nameIndex).append("\t\t\t//")
                        .append((context.cpInfo[nameIndex - 1] as ConstUtf8Info).utf8)
                }
            }
            return sb.toString()
        }

        @JvmStatic
        fun ByteArray.toLong(): Long =
            ((this[0].toLong() and 0xff) shl 56) +
                    ((this[1].toLong() and 0xff) shl 48) +
                    ((this[2].toLong() and 0xff) shl 40) +
                    ((this[3].toLong() and 0xff) shl 32) +
                    ((this[4].toLong() and 0xff) shl 24) +
                    ((this[5].toLong() and 0xff) shl 16) +
                    ((this[6].toLong() and 0xff) shl 8) +
                    (this[7].toLong() and 0xff)

        @JvmStatic
        fun ByteArray.toShort(): Short =
            (((this[0].toInt() and 0xff) shl 8) +
                    (this[1].toInt() and 0xff)).toShort()
    }

    fun process(name: String, remains: Iterator<String>) {
        val task = DecompileTask.instance(context)
        for (o in processorOptions) {
            if (o.matches(name)) {
                if (o.hasArg) {
                    if (remains.hasNext()) {
                        val other = remains.next()
                        o.process(task, name, other)
                    } else throw IllegalArgumentException()
                } else {
                    o.process(task, name, null)
                }
            }
        }
        task.classes.addLast(name)
    }

    fun processFile(name: String) {
        val task = DecompileTask.instance(context)
        if (Options.sysinfo) {
            task.report("Try to processing class $name")
        }
        val p = Path.of(name)
        val cr = ClassReader(p.readBytes())
        cr.read()
        task.report("${task.getMessage("main.files.report", p.toRealPath())}\nLastModified time:${p.getLastModifiedTime()}")
        // Report class file attributes
        for (attr in cr.classFileAttributeTable) {
            val name = (cr.cpInfo[attr.attributeNameIndex] as ConstUtf8Info).utf8
            when (name) {
                "SourceFile" ->
                    task.report(task.getMessage("main.files.resource",
                        (cr.cpInfo[(attr as SourceFileAttribute).sourceFileIndex] as ConstUtf8Info).utf8))
                "InnerClasses" -> {
                    val classIndices = (attr as InnerClassAttribute).innerClassesInfo
                    classIndices.forEach {
                        task.report(task.getMessage("main.files.innerclass",
                            innerClassInfo((cr.cpInfo[it.innerNameIndex] as ConstUtf8Info).utf8,
                                it.innerClassAccessFlags)))
                    }
                }
                "Deprecated" -> task.report("\tThis class is deprecated.")
            }
        }
        //ClassReader.report(cr)
        task.report(task.getMessage("main.class.head",
            Utils.parseClassAccessFlags(cr.accessFlags),
            ((cr.cpInfo[(cr.cpInfo[cr.thisClassIndex.toShort()
                .toInt() - 1] as ConstClassInfo).index - 1]) as ConstUtf8Info).utf8))
        // Use this method to report constant pool
        fun reportConstantPool() {
            task.report("Constant Pool:")
            cr.cpInfo.withIndex().forEach { (index, info) -> task.report(info.report(index, cr)) }
        }

        val mw: MethodWriter = if (Options.verbose) {
            reportConstantPool()
            MethodWriter(cr, context, Options.DisplayLevel.PRIVATE, lines_locals = true, instructions = true)
        } else {
            if (Options.constants)
                reportConstantPool()
            MethodWriter(cr, context, Options.level, Options.lines_locals, Options.instructions)
        }
        mw.process()
    }

    private fun innerClassInfo(name: String, accessFlags: Int): String {
        TODO()
    }
}