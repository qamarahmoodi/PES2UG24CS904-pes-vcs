# UE24CS242B : Operating Systems
# ORANGE PROBLEM -2
**NAME** : Qamar Ahmed <br>
**SRN** : PES2UG24CS904 <br>
**SEC** : D
- [📄 Report (PDF)](./PES2UG24CS904_D_ORANGE_2.pdf)


# 🚀 PES-VCS — Version Control System 

A lightweight version control system built in C that mimics the core ideas of Git, including object storage, staging, commits, and history tracking.

---

## 📌 Overview

PES-VCS is a simplified implementation of how Git works internally.
Instead of storing file differences, it stores **complete snapshots** of the project using:

* Content-addressable storage (SHA-256 hashing)
* Tree structures for directories
* Commit objects for history tracking

This project helped in understanding **filesystem design, hashing, and version control internals**.

---

## 🧠 Key Concepts Implemented

* 🔹 Blob objects (file contents)
* 🔹 Tree objects (directory structure)
* 🔹 Commit objects (snapshots + history)
* 🔹 Index (staging area)
* 🔹 HEAD and branch references
* 🔹 Content-addressable storage

---

## 🛠️ Features

* `pes init` → Initialize repository
* `pes add <file>` → Stage files
* `pes status` → Show file states
* `pes commit -m "msg"` → Create commit
* `pes log` → Show commit history

---

## 📂 Project Structure

```
.
├── object.c        # Object storage (blob/tree/commit)
├── tree.c          # Directory structure handling
├── index.c         # Staging area implementation
├── commit.c        # Commit creation and history
├── pes.c           # CLI interface
├── .pes/           # Repository metadata (created after init)
```

---

## ⚙️ Build & Run

### 🔧 Compile

```bash
make
```

### ▶️ Run

```bash
./pes init
./pes add file.txt
./pes commit -m "Initial commit"
./pes log
```

---

## 📊 How It Works (High Level)

1. **Add**

   * File is hashed → stored as blob
   * Entry added to index

2. **Commit**

   * Tree is built from index
   * Commit object created
   * HEAD updated

3. **Storage**

   * Objects stored in:

     ```
     .pes/objects/<hash>
     ```

---

## 🧪 Testing

```bash
make test_objects
./test_objects

make test_tree
./test_tree

make test-integration
```

---

## 📈 Learning Outcomes

* Understood how Git stores data internally
* Learned about hashing and data integrity
* Implemented filesystem-like structures
* Gained experience with low-level C programming

---


## 👤 Author

**Qamar Ahmed**
PES University

---

## 📚 References

* Git Internals (Pro Git Book)
* Git from the Inside Out
* Official Git Documentation

---
