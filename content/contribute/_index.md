---
menu:
  after:
    name: contribute
    weight: 5
title: Contribute
bookFlatSection: true
type: docs
---

# **Contribute**

Hey There! Looks like you are here for contributing to the wiki...Let me help you with a few pointers!

* The aim of this open-source project to create a central repository for all the cybersecurity content, which can be consumed by security researchers and newbies in the field.
* You can add content related to any field and this is also a great place to showcase the content you have created.
* The scope of the project is whatever you think can help out folks get started in the cyber security.
* We have hosted everything on to Github, click on the button and it will take you to Github 
  <br>
  {{< button href="https://github.com/payatu/cybersec-wiki" >}}<div class="flex align-center">Contribute</div>{{< /button >}}

## Structure
The structure is required for uniformity, so here are a few template, to help you curate the content.

{{< details title="To add a new category" open=false >}}

A category is the high level overview. For example - "**Application Security**" is a category.

Steps - 
Create a new directory in {{< external title="docs" href="" >}} directory. Add a new file inside the newly created directory called **_index.md** with the following content in it.
```markdown
---
bookFlatSection: true
bookCollapseSection: true
---

<!-- Your content here. -->
```

a new category will be created.

Repeat the same step to create sub categories as well.

Each **Category will contain an `images/` folder.** 

The directory structure will look something like this (example for cloud security) - 
```shell
docs/
├─ cloud-security/
│  ├─ aws/
│  │  ├─ labs.md
│  │  ├─ reports.md
│  ├─ images/
│  ├─ _index.md
```

{{< /details >}}

<br>

{{< details title="To add a new page" open=false >}}
Each page will contain the following content - 
```markdown
---
title: <!-- Title of the page here. -->
---

<!-- Your content here. -->
```

Images can be used in each page by using the complete link - `content/docs/cloud-security/images/image.png`
Example - 
```markdown
![Alt text](content/docs/cloud-security/images/image.png)
```
{{< /details >}}

## Infrastructure 
The wiki is built on the Hugo. If you can help with any improvements, feature additions, etc. You can [create an Issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-an-issue) and we can discuss it over there.

## Cool Features
{{< details title="Linking an external URL" open=false >}}
```tpl
{{</* external title="" href="" */>}}
```
It will add a external link symbol after the link for the UX and will open up the link in a new tab.
{{< /details >}}

<br>
{{< details title="Linking an internal document" open=false >}}
```tpl
{{</* ref "<!-- document/path/here -->" */>}}
```
It will help hugo internally process the document easily.
{{< /details >}}

Other cool elements to be added can be found in the {{<external title="shortcode" href="https://github.com/alex-shpak/hugo-book#shortcodes">}} section.
