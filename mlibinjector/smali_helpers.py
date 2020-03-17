smali_prologue = """

	const-string v0, "%s"

	invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

"""
smali_direct_method = """

.method static constructor <clinit>()V
	.locals 1

	.prologue
	{}

	return-void
.end method


""".format(smali_prologue)
