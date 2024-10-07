if(process.env.NODE_ENV != "production") {
    require('dotenv').config(); 
}
const express = require("express");
const app = express()
const mongoose = require("mongoose");
const Listing = require("./models/listing.js");
const path = require("path");
const methodOverride = require("method-override");
const ejsMate = require("ejs-mate");
const wrapAsync = require("./utils/wrapAsync.js");
const ExpressError = require("./utils/ExpressError.js");
const { listingSchema, reviewSchema } = require("./schema.js");
const Review = require("./models/review.js");
const session = require("express-session");
const flash = require("connect-flash");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const User = require("./models/user.js");
const multer = require("multer");
const {storage} = require("./cloudConfig.js");
const upload = multer({ storage });
const MongoStore = require('connect-mongo');



const dbUrl  = process.env.ATLASDB_URL;


main()
    .then(() => {
        console.log("connected to db")
    })
    .catch(err => console.log(err));

async function main() {
    await mongoose.connect(dbUrl);
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));

app.engine("ejs", ejsMate);

app.use(express.static(path.join(__dirname, "/public")));

const store = MongoStore.create({
    mongoUrl: dbUrl,
    crypto: {
        secret: process.env.SECRET,
    },
    touchAfter: 24 * 3600,
});

store.on("error", ()=>{
    console.log("ERROR IN SESSION STORE",err)
})

const sessionOptions = {
    store,
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        expires: Date.now() + 7 * 24 * 60 * 60 * 1000,
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,

    },
};


app.use(session(sessionOptions));
app.use(flash());

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.use((req, res, next) => {
    res.locals.success = req.flash("success");
    res.locals.error = req.flash("error");
    res.locals.currUser = req.user;
    next();
});


// ------------------------------------------   Functions   ----------------------------------------------------------

const validateListing = (req, res, next) => {
    let { error } = listingSchema.validate(req.body);
    if (error) {
        let errorMsg = error.details.map((el) => el.message).join(",");
        throw new ExpressError(400, errorMsg)
    } else {
        next();
    }
};

const validateReview = (req, res, next) => {
    let { error } = reviewSchema.validate(req.body);
    if (error) {
        let errorMsg = error.details.map((el) => el.message).join(",");
        throw new ExpressError(400, errorMsg)
    } else {
        next();
    }
};

const isLoggedIn = (req, res, next) => {
    if (!req.isAuthenticated()) {
        req.session.redirectUrl = req.originalUrl;
        req.flash("error", "You must be logged in to do this task");
        return res.redirect("/login");
    }
    next();
};

const saveRedirectUrl = (req, res, next) => {
    if (req.session.redirectUrl) {
        res.locals.redirectUrl = req.session.redirectUrl;
    }
    next();
};

const isOwner = async (req, res, next) => {
    let { id } = req.params;
    let listing = await Listing.findById(id);
    if (!listing.owner._id.equals(res.locals.currUser._id)) {
        req.flash("error", "You are not the owner of this listing");
        return res.redirect(`/listings/${id}`);
    }
    next();
}
const isAuthor = async (req, res, next) => {
    let { id, reviewId } = req.params;
    let review = await Review.findById(reviewId);
    if (!review.author._id.equals(res.locals.currUser._id)) {
        req.flash("error", "You are not the author of this review");
        return res.redirect(`/listings/${id}`);
    }
    next();
}

// -----------------------------------------------  Listing  ----------------------------------------------------------------

// index route 
app.get("/listings", wrapAsync(async (req, res) => {
    const { query } = req.query;
    let searchRegex = new RegExp(query, 'i');

    const allListings = await Listing.find({
        $or: [
            { title: searchRegex },
            { location: searchRegex },
            { country: searchRegex }
        ]
    });

    res.render("./listings/index.ejs", { allListings });
}));



// new route

app.get("/listings/new", isLoggedIn, wrapAsync(async (req, res) => {
    res.render("./listings/new.ejs")
}));


// show route 

app.get("/listings/:id", wrapAsync(async (req, res) => {
    const { id } = req.params;
    
    const listing = await Listing.findById(id).populate({
        path: "reviews",
        populate: { path: "author" }
    }).populate("owner");
    
    if (!listing) {
        req.flash("error", "Listing that you requested, doesn't exist");
        return res.redirect("/listings");
    }

    const address = listing.location;
    const apiKey = 'M71NvRBSUXVdkBcX50XE';
    const geourl = `https://api.maptiler.com/geocoding/${encodeURIComponent(address)}.json?key=${apiKey}`;
    
    let coordinates;
    try {
        const response = await fetch(geourl);
        const data = await response.json();
        
        if (data && data.features && data.features.length > 0) {
            coordinates = data.features[0].geometry.coordinates;  // longitude, latitude
        } else {
            coordinates = [0, 0];  // Default coordinates if no data is returned
        }
    } catch (error) {
        console.error('Error fetching coordinates:', error);
        coordinates = [0, 0];  // Default coordinates in case of error
    }

    res.render("./listings/show.ejs", { listing, coordinates });
}));

// create route 

app.post("/listings", isLoggedIn , upload.single('listing[image]') , validateListing  , wrapAsync(async (req, res, next) => {
    let url = req.file.path;
    let  filename = req.file.filename;

    // let listing = req.body.listing;
    // let newlisting = new Listing(listing);

    const newListing = new Listing(req.body.listing);
    newListing.owner = req.user._id;
    newListing.image = {url,filename};
    await newListing.save();
    req.flash("success", "New listing created!");
    res.redirect("/listings");

})
);

// edit route 

app.get("/listings/:id/edit", isLoggedIn, isOwner, wrapAsync(async (req, res) => {
    const { id } = req.params;
    const listing = await Listing.findById(id);
    if(!listing){
        req.flash("error","Listing you requested does not exist");
        res.redirect("/listings")
    }
    let originalImageUrl = listing.image.url;
    originalImageUrl = originalImageUrl.replace("/upload","/upload/w_250");
    res.render("./listings/edit.ejs", { listing , originalImageUrl });

}))


// update route 

app.put("/listings/:id", isLoggedIn, isOwner, upload.single("listing[image]") , validateListing, wrapAsync(async (req, res) => {
    let { id } = req.params;
    let listing = await Listing.findByIdAndUpdate(id, { ...req.body.listing });
     
    if(typeof req.file !== "undefined"){
    let url = req.file.path;
    let  filename = req.file.filename;
    listing.image = {url,filename};
    await listing.save();        
    }

    req.flash("success", "Listing updated!");
    res.redirect(`/listings/${id}`);

}))
// delete route 

app.delete("/listings/:id", isLoggedIn, isOwner, wrapAsync(async (req, res) => {
    const { id } = req.params;
    let deletedList = await Listing.findByIdAndDelete(id);
    console.log(deletedList);
    req.flash("success", "Listing deleted!");
    res.redirect("/listings");

}))

// --------------------------------------------------   User   ----------------------------------------------------------------------------------------------------------

app.get("/signup", (req, res) => {
    res.render("users/signup.ejs")
});

app.post("/signup", wrapAsync(async (req, res) => {
    try {
        let { username, email, password } = req.body;
        const newUser = new User({ email, username });
        const registeredUser = await User.register(newUser, password);
        console.log(registeredUser);
        req.login(registeredUser, (err) => {
            if (err) {
                return next(err);
            }
            req.flash("success", "Welcome to ArcadiaLuxe");
            res.redirect("/listings");
        })

    } catch (err) {
        req.flash("error", err.message);
        res.redirect("/signup");
    }
}));

app.get("/login", (req, res) => {
    res.render("users/login.ejs")
});

app.post("/login", saveRedirectUrl, passport.authenticate("local", { failureRedirect: "/login", failureFlash: true }), async (req, res) => {
    req.flash("success", "Welcome back to ArcadiaLuxe, You're Logged in.");
    let redirectUrl = res.locals.redirectUrl || "/listings";
    res.redirect(redirectUrl);
})

app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.flash("success", "Logged out successfully");
        res.redirect("/listings");
    });
});

// --------------------------------------------------   Review   ----------------------------------------------------------------------------------------------------------

// post review route 

app.post("/listings/:id/reviews", isLoggedIn, validateReview, wrapAsync(async (req, res) => {
    let listing = await Listing.findById(req.params.id);
    let newReview = new Review(req.body.review);
    newReview.author = req.user._id;

    listing.reviews.push(newReview);

    await newReview.save();
    await listing.save();

    req.flash("success", "New review created!");


    res.redirect(`/listings/${listing._id}`);

}));

// delete review route

app.delete("/listings/:id/reviews/:reviewId", isLoggedIn, isAuthor, wrapAsync(async (req, res) => {
    let { id, reviewId } = req.params;
    await Listing.findByIdAndUpdate(id, { $pull: { reviews: reviewId } });
    await Review.findByIdAndDelete(reviewId);
    req.flash("success", "Review deleted!");

    res.redirect(`/listings/${id}`);

}));

// -------------------------------------------------Search-------------------------------------------------------------------------------------------
// search route
// app.get('/search', wrapAsync(async (req, res) => {
//     const { query } = req.query; // Get the search query

//     let searchResults = await Listing.find({
//         $or: [
//             { title: { $regex: query, $options: 'i' } }, // Case-insensitive search
//         ]
//     });

//     res.render('./listing/index.ejs', { searchResults, query }); // Render the search results
// }));


// -----------------------------------------------    MW    -----------------------------------------------------------------------------------------

// app.all("*", (req, res, next) => {
//     next(new ExpressError(404, "page not found!"));
// })


app.use((err, req, res, next) => {
    let { statusCode = 500, message = "something went wrong!" } = err;
    res.status(statusCode).render("./listings/error.ejs", { err });
});



app.listen(8080, (req, res) => {
    console.log('Server started on http://localhost:8080/listings')
})

