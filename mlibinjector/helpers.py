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

xml_netsecconf = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
	<base-config cleartextTrafficPermitted="true">
		<trust-anchors>
			<certificates src="system" />
			<certificates src="user" />
		</trust-anchors>
	</base-config>
</network-security-config>"""
