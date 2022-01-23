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

{{< hint info >}}
The `_index.md` file acts as the index for that specific directory.
{{< /hint >}}

{{< details title="To add a new category" open=false >}}

A category is the high level overview. For example - "**Application Security**" is a category.

Steps - 
Create a new directory in {{< external title="docs" href="https://github.com/payatu/cybersec-wiki/tree/main/content/docs" >}} directory. Add a new file inside the newly created directory called **_index.md** with the following content in it.

```markdown
---
title: <!-- Category Name Here. -->
bookCollapseSection: true
---

<!-- Your content here. -->
```

a new category will be created.

Each **Category will contain an `images/` folder.** 

Directory Structure - 
```
content/
├─ docs/
│  ├─ category-name/
│  │  ├─ images/
│  │  ├─ _index.md
```

{{< /details >}}

<br>

{{< details title="Create a New Sub Category" open=false >}}

To create a sub category in side a category, we need to create a directory inside the main category, which will contain all the different markdown files of different content.

```markdown
---
title: <!-- SubCategory Name Here. -->
bookCollapseSection: true
---

<!-- Your content here. -->
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

Images can be used in each page by using the complete link - `content/docs/<category-name>/images/<image-name>.<extension>`
Example - 
```markdown
![Alt text](content/docs/cloud-security/images/image.png)
```
{{< /details >}}

## Infrastructure 
The wiki is built on the Hugo. If you can help with any improvements, feature additions, etc. Create an Issue over GitHub and we can discuss it over there.

## Additional Features

{{< details title="Linking an Internal Document" open=false >}}
```tpl
{{</* relref "<!-- document/path/here -->" */>}}
```
It will help hugo internally process the document easily.
{{< /details >}}

Other cool elements to be added can be found in the {{<external title="shortcode" href="https://github.com/alex-shpak/hugo-book#shortcodes">}} section.

## Test Locally

1. Clone the repository to make changes locally - 
    ```shell
    git clone git@github.com:payatu/cybersec-wiki.git
    ```

2. Install [Hugo Extended Latest Version](https://github.com/gohugoio/hugo/releases).
   
3. From the parent location of repository where the source code is, run 
      ```shell
      hugo server
      ```
   It will start a local server to test the changes that you have made, in terms of look, feel and content.

4. Once satisfied with the changes made, push the changes to GitHub.
5. Create a Pull Request and if everything looks fine, we will be merging the content to the Cyber Security Wiki.