libraryDependencies ++= Seq(
  "javax.servlet" % "servlet-api" % "2.5" % "provided",
  "org.scalatra" %% "scalatra" % "2.0.2",
  "org.openid4java" % "openid4java" % "0.9.7",
  "commons-codec" % "commons-codec" % "1.4",
  "commons-lang" % "commons-lang" % "2.5"
)


scalaVersion := "2.9.1"

crossScalaVersions ++= Seq("2.9.0-1", "2.9.0", "2.8.1")

publishArtifact := true

organization := "com.gu"

name := "scalatra-openid-consumer"

version in ThisBuild := "0.1.11"

publishTo <<= (version) { version: String =>
    val publishType = if (version.endsWith("SNAPSHOT")) "snapshots" else "releases"
    Some(
        Resolver.file(
            "guardian github " + publishType,
            file(System.getProperty("user.home") + "/guardian.github.com/maven/repo-" + publishType)
        )
    )
}
