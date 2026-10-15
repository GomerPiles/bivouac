package vm

import "encoding/xml"

// entitled reports whether an entitlements plist, as `codesign -d
// --entitlements - --xml` prints it, sets key to true in its top-level dict.
func entitled(plist []byte, key string) bool {
	var doc struct {
		Dict struct {
			Items []struct {
				XMLName xml.Name
				Text    string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"dict"`
	}
	if xml.Unmarshal(plist, &doc) != nil {
		return false
	}
	items := doc.Dict.Items
	for i := 0; i+1 < len(items); i++ {
		if items[i].XMLName.Local == "key" && items[i].Text == key {
			return items[i+1].XMLName.Local == "true"
		}
	}
	return false
}
