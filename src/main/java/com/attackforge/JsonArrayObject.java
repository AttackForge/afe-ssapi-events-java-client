package com.attackforge;

import org.json.JSONArray;
import org.json.JSONObject;

public class JsonArrayObject {
    public JsonArrayObject(JSONObject object, JSONArray array) {
        this.object = object;
        this.array = array;
    }

    public JSONObject object = null;
    public JSONArray array = null;
}
