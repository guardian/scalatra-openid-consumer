libraryDependencies ++= Seq(
  "javax.servlet" % "servlet-api" % "2.5" % "provided",
  "org.scalatra" %% "scalatra" % "2.0.2",
  "com.google.inject" % "guice" % "2.0",
  "commons-codec" % "commons-codec" % "1.4",
  "commons-lang" % "commons-lang" % "2.5"
)

// Adding the openid4java dependency using ivyXML, due to bug in sbt.
// com.google.code.guice is excluded as it is no longer available,
// sbt 0.11.* can only exclude jars, so using ivyXML syntax to work around.

ivyXML :=
  <dependency org="org.openid4java" name="openid4java-consumer" rev="0.9.6">
      <exclude org="com.google.code.guice" module="guice"/>
  </dependency>



scalaVersion := "2.9.1"

crossScalaVersions ++= Seq("2.9.0-1", "2.9.0", "2.8.1")

publishArtifact := true

organization := "com.gu"

name := "scalatra-openid-consumer"

version in ThisBuild := "0.1.8"

publishTo <<= (version) { version: String =>
    val publishType = if (version.endsWith("SNAPSHOT")) "snapshots" else "releases"
    Some(
        Resolver.file(
            "guardian github " + publishType,
            file(System.getProperty("user.home") + "/guardian.github.com/maven/repo-" + publishType)
        )
    )
}
