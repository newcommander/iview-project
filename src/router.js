const routers = [
    {
        path: '/',
        meta: {
            title: ''
        },
        component: (resolve) => require(['./views/index.vue'], resolve)
    },
    {
        path: '/console',
        meta: {
            title: 'Console'
        },
        component: (resolve) => require(['./views/console/main.vue'], resolve)
    }
];
export default routers;
