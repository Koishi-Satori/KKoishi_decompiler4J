@file:Suppress("LocalVariableName")

package top.kkoishi.decomp.classfile

import top.kkoishi.cv4j.Attribute_info
import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.ClassReader.toInt
import top.kkoishi.cv4j.ConstPoolInfo
import top.kkoishi.cv4j.ConstPoolInfo.*
import top.kkoishi.cv4j.DecompilerException
import top.kkoishi.cv4j.attr.InnerClassAttribute
import top.kkoishi.cv4j.attr.SourceFileAttribute
import top.kkoishi.cv4j.cp.ConstClassInfo
import top.kkoishi.cv4j.cp.ConstNameAndTypeInfo
import top.kkoishi.cv4j.cp.ConstUtf8Info
import top.kkoishi.decomp.*
import top.kkoishi.decomp.Utils.REF_names
import top.kkoishi.decomp.Utils.formatNumber
import top.kkoishi.decomp.Utils.length
import top.kkoishi.decomp.classfile.FileProcessor.Companion.toShort
import java.io.IOException
import java.nio.file.Path
import kotlin.io.path.*
import kotlin.jvm.Throws

class FileProcessor(val context: Context) {
    companion object {
        @JvmStatic
        var processorOptions: Array<Option> = arrayOf(
            object : Option(true, "-cp", "-classpath") {
                override fun process(task: DecompileTask, opt: String, arg: String?) {
                    Options.classpath = true
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
            val buf = StringBuilder(formatNumber(index, context.cpInfo.size.length(), false, "\t#"))
            buf.append(" = ").append(constantsNames[this.tag().toInt()]).append("\t\t")
            fun reportRefImpl(classIndex: Int, nameAndTypeIndex: Int) {
                with(context) {
                    val classInfo = cpInfo[classIndex - 1]
                    @Suppress("UNCHECKED_CAST") val datum =
                        cpInfo[nameAndTypeIndex - 1].data() as Array<ByteArray>
                    buf.append((cpInfo[(classInfo.data() as ByteArray).toShort().toInt() - 1]
                            as ConstUtf8Info).utf8).append('.')
                        .append((cpInfo[datum[0].toShort().toInt() - 1] as ConstUtf8Info).utf8)
                        .append('.').append((cpInfo[datum[1].toShort().toInt() - 1]
                                as ConstUtf8Info).utf8)
                }
            }
            when (this.tag()) {
                CONSTANT_UTF8_INFO -> buf.append((this as ConstUtf8Info).utf8)
                CONSTANT_INTEGER_INFO -> buf.append(toInt(this.data() as ByteArray))
                CONSTANT_FLOAT_INFO -> buf.append(Float.fromBits(toInt(this.data() as ByteArray)))
                CONSTANT_LONG_INFO -> buf.append((this.data() as ByteArray).toLong())
                CONSTANT_DOUBLE_INFO -> buf.append(Double.fromBits((this.data() as ByteArray).toLong()))
                CONSTANT_CLASS_INFO -> {
                    val i = (this.data() as ByteArray).toShort().toInt()
                    buf.append('#').append(i).append("\t\t\t//").append((context.cpInfo[i - 1] as ConstUtf8Info).utf8)
                }
                CONSTANT_STRING_INFO -> buf.append((context.cpInfo[(this.data() as ByteArray).toShort()
                    .toInt() - 1] as ConstUtf8Info).utf8)
                CONSTANT_NAME_AND_TYPE_INFO -> {
                    @Suppress("UNCHECKED_CAST") val data = this.data() as Array<ByteArray>
                    val name_index = data[0].toShort().toInt()
                    val descriptor_index = data[1].toShort().toInt()
                    buf.append('#').append(name_index).append('#')
                        .append(descriptor_index).append("\t\t\t//")
                        .append((context.cpInfo[name_index - 1] as ConstUtf8Info).utf8)
                        .append((context.cpInfo[descriptor_index - 1] as ConstUtf8Info).utf8)
                }
                CONSTANT_FIELDREF_INFO, CONSTANT_METHODREF_INFO, CONSTANT_INTERFACE_METHODREF -> {
                    // Report the CONSTANT_Class_info and CONSTANT_NameAndType_info.
                    @Suppress("UNCHECKED_CAST") val data = this.data() as Array<ByteArray>
                    val class_index = data[0].toShort().toInt()
                    val name_and_type_index = data[1].toShort().toInt()
                    buf.append('#').append(class_index).append(".#")
                        .append(name_and_type_index).append("\t\t\t//")
                    reportRefImpl(class_index, name_and_type_index)
                }
                CONSTANT_METHOD_HANDLE_INFO -> {
                    @Suppress("UNCHECKED_CAST") val datum =
                        this.data() as Array<ByteArray>
                    val reference_kind: Byte = datum[0][0]
                    val reference_index = toInt(datum[1])
                    buf.append('*').append(reference_kind).append(" #")
                        .append(reference_index).append("\t\t\t//").append(REF_names[reference_kind - 1])
                        .append(' ')
                    @Suppress("UNCHECKED_CAST") val data =
                        context.cpInfo[reference_index - 1].data() as Array<ByteArray>
                    val class_index = data[0].toShort().toInt()
                    val name_and_type_index = data[1].toShort().toInt()
                    reportRefImpl(class_index, name_and_type_index)
                }
                CONSTANT_METHOD_TYPE_INFO -> {
                    val descriptor_index = (this.data() as ByteArray).toShort().toInt()
                    buf.append('#').append(descriptor_index).append("\t\t\t//")
                        .append((context.cpInfo[descriptor_index - 1] as ConstUtf8Info).utf8)
                }
                CONSTANT_DYNAMIC, CONSTANT_INVOKE_DYNAMIC_INFO -> {
                    @Suppress("UNCHECKED_CAST") val datum =
                        this.data() as Array<ByteArray>
                    val bootstrap_method_attr_index = toInt(datum[0])
                    val name_and_type_index = toInt(datum[1])
                    buf.append("bootstrap method#").append(bootstrap_method_attr_index)
                        .append("  #").append(name_and_type_index)
                    with(context) {
                        @Suppress("UNCHECKED_CAST") val nameType =
                            (cpInfo[name_and_type_index - 1] as ConstNameAndTypeInfo).data() as Array<ByteArray>
                        val name_index = nameType[0].toShort().toInt()
                        val descriptor_index = nameType[1].toShort().toInt()
                        buf.append("\t\t//")
                            .append((context.cpInfo[name_index - 1] as ConstUtf8Info).utf8)
                            .append((context.cpInfo[descriptor_index - 1] as ConstUtf8Info).utf8)
                    }
                }
                CONSTANT_MODULE, CONSTANT_PACKAGE -> {
                    val name_index = (this.data() as ByteArray).toShort().toInt()
                    buf.append('#').append(name_index).append("\t\t\t//")
                        .append((context.cpInfo[name_index - 1] as ConstUtf8Info).utf8)
                }
            }
            return buf.toString()
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

    @Throws(IOException::class)
    private fun getFilePath(name: String): Path {
        var p = Path.of(name)
        if (name.endsWith(".class")) {
            if (p.exists())
                return p
            val cur = System.getProperty("workdir") ?: Utils.cwd
            p = Path.of("$cur/$name")
            if (p.exists())
                return p
        } else {
            if (Options.classpath) {
                val task = DecompileTask.instance(context)
                System.getProperties()
                if (p.exists()) {
                    val classes = p.readText()
                    TODO()
                }
            }
        }
        throw IOException("Can not find file $p")
    }

    fun parseFileAttribute(attr: Attribute_info, task: DecompileTask, cr: ClassReader) {
        val attribute_name = (cr.cpInfo[attr.attributeNameIndex - 1] as ConstUtf8Info).utf8
        when (attribute_name) {
            "SourceFile" ->
                task.report(task.getMessage("main.files.resource",
                    (cr.cpInfo[(attr as SourceFileAttribute).sourceFileIndex - 1] as ConstUtf8Info).utf8))
            "InnerClasses" -> {
                val classIndices = (attr as InnerClassAttribute).innerClassesInfo
                classIndices.forEach {
                    task.report(task.getMessage("main.files.innerclass",
                        innerClassInfo((cr.cpInfo[it.innerNameIndex - 1] as ConstUtf8Info).utf8,
                            it.innerClassAccessFlags)))
                }
            }
            "Deprecated" -> task.report("\tThis class is deprecated.")
            "SourceDebugExtension" -> {

            }
        }
    }

    @Suppress("MoveVariableDeclarationIntoWhen")
    fun processFile(name: String) {
        val task = DecompileTask.instance(context)
        if (Options.sysinfo) {
            task.report("Try to processing class $name")
        }
        val p = getFilePath(name)
        val cr = ClassReader(p.readBytes())
        cr.read()
        task.report("${
            task.getMessage("main.files.report",
                p.toRealPath())
        }\nLastModified time:${p.getLastModifiedTime()}")
        // Report class file attributes
        for (attr in cr.classFileAttributeTable)
            parseFileAttribute(attr, task, cr)
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

        if (Options.constants || Options.verbose)
            reportConstantPool()

        val fw: FieldWriter = if (Options.verbose)
            FieldWriter(cr, context, Options.DisplayLevel.PRIVATE, access = true, signature = true, constants = true)
        else
            FieldWriter(cr, context, Options.level, Options.access, Options.signature, constants = Options.constants)
        fw.process()

        val mw: MethodWriter = if (Options.verbose) {
            MethodWriter(cr,
                context,
                Options.DisplayLevel.PRIVATE,
                lines_locals = true,
                instructions = true,
                access = true,
                signature = true)
        } else {
            MethodWriter(cr,
                context,
                Options.level,
                Options.lines_locals,
                Options.instructions,
                Options.access,
                Options.signature)
        }
        mw.process()
    }

    private fun innerClassInfo(name: String, accessFlags: Int): String {
        return Utils.parseClassAccessFlags(accessFlags) + ' ' + name
    }
}