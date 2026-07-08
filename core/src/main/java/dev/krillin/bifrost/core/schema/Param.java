package dev.krillin.bifrost.core.schema;
/** Schema of a UDT parameter: name + type name as returned by ParameterDataType.toString(). */
public record Param(String name, String type) {}
